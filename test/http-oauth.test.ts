import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createDoorkingHttpApp } from '../src/http.ts';

test('Streamable HTTP MCP: OAuth 2.1 metadata, DCR + PKCE authorization flow, and authenticated tool call', async () => {
  const validToken = `dks_${'a'.repeat(64)}`;
  const mockApi = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const send = (code: number, body: unknown) => {
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (req.method === 'POST' && req.url === '/api/session') {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (body.user === 'alice' && body.password === 'correct-horse-battery') {
          return send(200, { ok: true, token: validToken });
        }
        return send(401, { error: 'Wrong username or password' });
      }
      if (req.method === 'GET' && req.url === '/api/session') {
        if (req.headers.authorization === `Bearer ${validToken}`) {
          return send(200, { loggedIn: true, user: 'alice' });
        }
        return send(200, { loggedIn: false });
      }
      if (req.method === 'GET' && req.url === '/api/gates') {
        if (req.headers.authorization !== `Bearer ${validToken}`) return send(401, { error: 'Not logged in' });
        return send(200, { gates: [{ phoneNumber: '5550100', siteName: 'Main Gate', addedAt: '2026-11-01T00:00:00Z', role: 'admin' }] });
      }
      if (req.method === 'GET' && req.url === '/api/key-info') {
        if (req.headers.authorization === 'Bearer dkg_0123456789ab_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB') {
          return send(200, {
            id: '0123456789ab',
            phone: '5550100',
            name: 'auggie-staging',
            role: 'editor',
            scopes: ['gate:read', 'directory:read', 'directory:write', 'transactions:read'],
          });
        }
        return send(401, { error: 'Invalid or expired API key' });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100') {
        return send(200, { phoneNumber: '5550100', siteName: 'Main Gate', addedAt: '2026-11-01T00:00:00Z', role: 'editor' });
      }
      return send(404, { error: 'Not found' });
    });
  });

  await new Promise<void>((resolve) => mockApi.listen(0, '127.0.0.1', resolve));
  const apiPort = (mockApi.address() as AddressInfo).port;

  // Bind MCP HTTP app on ephemeral port
  const mcpServer = http.createServer();
  await new Promise<void>((resolve) => mcpServer.listen(0, '127.0.0.1', resolve));
  const mcpPort = (mcpServer.address() as AddressInfo).port;
  const mcpOrigin = `http://127.0.0.1:${mcpPort}`;

  const { app } = createDoorkingHttpApp({
    apiBaseUrl: `http://127.0.0.1:${apiPort}`,
    publicIssuerUrl: mcpOrigin,
    host: '127.0.0.1',
    policy: { allowWorkingCopyWrites: true, allowPhysical: false },
  });
  mcpServer.on('request', app);

  try {
    // 1. OAuth 2.0 Protected Resource Metadata (RFC 9728) & AS Metadata (RFC 8414)
    const prm = await (await fetch(`${mcpOrigin}/.well-known/oauth-protected-resource/mcp`)).json() as { resource: string; authorization_servers: string[] };
    assert.strictEqual(prm.resource, `${mcpOrigin}/mcp`);
    assert.ok(prm.authorization_servers.length >= 1);

    const asMeta = await (await fetch(`${mcpOrigin}/.well-known/oauth-authorization-server`)).json() as {
      authorization_endpoint: string; token_endpoint: string; registration_endpoint: string;
    };
    assert.ok(asMeta.authorization_endpoint.endsWith('/authorize'));
    assert.ok(asMeta.token_endpoint.endsWith('/token'));

    // 2. Unauthenticated POST /mcp returns 401 with WWW-Authenticate resource_metadata
    const unauth = await fetch(`${mcpOrigin}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.strictEqual(unauth.status, 401);
    assert.match(unauth.headers.get('www-authenticate') || '', /resource_metadata=/);

    // 3. Dynamic Client Registration (RFC 7591)
    const reg = await (await fetch(asMeta.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Test MCP Client',
        redirect_uris: ['http://127.0.0.1:9999/cb'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    })).json() as { client_id: string };
    assert.match(reg.client_id, /^dkmcp_/);

    // 4. PKCE authorize -> consent -> token exchange
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const authUrl = new URL(asMeta.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', reg.client_id);
    authUrl.searchParams.set('redirect_uri', 'http://127.0.0.1:9999/cb');
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', 'xyz123');
    authUrl.searchParams.set('scope', 'doorking:read');

    const consentHtml = await (await fetch(authUrl)).text();
    const consentId = /name="consent_id" value="([^"]+)"/.exec(consentHtml)?.[1];
    assert.ok(consentId, 'consent page renders consent_id');

    const approveRes = await fetch(`${mcpOrigin}/oauth/approve`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        consent_id: consentId!,
        user: 'alice',
        password: 'correct-horse-battery',
        decision: 'approve',
      }),
    });
    assert.strictEqual(approveRes.status, 302);
    const loc = new URL(approveRes.headers.get('location')!);
    assert.strictEqual(loc.searchParams.get('state'), 'xyz123');
    const authCode = loc.searchParams.get('code')!;
    assert.ok(authCode);

    const tokenRes = await (await fetch(asMeta.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: reg.client_id,
        code: authCode,
        redirect_uri: 'http://127.0.0.1:9999/cb',
        code_verifier: verifier,
      }),
    })).json() as { access_token: string; scope: string };
    assert.strictEqual(tokenRes.access_token, validToken);
    assert.strictEqual(tokenRes.scope, 'doorking:read');

    // 5. Connect official StreamableHTTPClientTransport with OAuth bearer token & call list_gates
    const transport = new StreamableHTTPClientTransport(new URL(`${mcpOrigin}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${tokenRes.access_token}` } },
    });
    const client = new Client({ name: 'http-test-client', version: '1.0.0' });
    await client.connect(transport);
    try {
      const tools = (await client.listTools()).tools.map((t) => t.name);
      assert.ok(tools.includes('list_gates'));
      assert.ok(!tools.includes('upsert_directory_entry'), 'doorking:read scope must not expose Tier 1 writes');
      const gatesRes = await client.callTool({ name: 'list_gates', arguments: {} });
      const parsed = JSON.parse((gatesRes.content as Array<{ text: string }>)[0].text);
      assert.strictEqual(parsed.gates[0].siteName, 'Main Gate');
    } finally {
      await client.close();
    }

    // 6. Direct scoped dkg_ API key auto-discovers gate & staging scope via /api/key-info
    const apiKeyTransport = new StreamableHTTPClientTransport(new URL(`${mcpOrigin}/mcp`), {
      requestInit: { headers: { Authorization: 'Bearer dkg_0123456789ab_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' } },
    });
    const keyClient = new Client({ name: 'apikey-http-client', version: '1.0.0' });
    await keyClient.connect(apiKeyTransport);
    try {
      const tools = (await keyClient.listTools()).tools.map((t) => t.name);
      assert.ok(tools.includes('upsert_directory_entry'), 'staging-scoped editor key enables Tier 1 working-copy writes');
      assert.ok(!tools.includes('send_to_gate'), 'physical tools remain disabled');
      const gatesRes = await keyClient.callTool({ name: 'list_gates', arguments: {} });
      const parsed = JSON.parse((gatesRes.content as Array<{ text: string }>)[0].text);
      assert.strictEqual(parsed.gates[0].phoneNumber, '5550100');
    } finally {
      await keyClient.close();
    }
  } finally {
    await new Promise<void>((resolve) => mcpServer.close(() => resolve()));
    await new Promise<void>((resolve) => mockApi.close(() => resolve()));
  }
});
