#!/usr/bin/env node
/**
 * @module http
 *
 * Remote Streamable HTTP MCP server + OAuth 2.1 Authorization Server powered by `@modelcontextprotocol/sdk`
 * (`createMcpExpressApp`, `mcpAuthRouter`, `requireBearerAuth`, `StreamableHTTPServerTransport`).
 *
 * Every request is authenticated with the caller's own Bearer token (OAuth-issued `dks_` user session or scoped
 * `dkg_` gate API key) and forwarded directly to `api/` over REST — zero shared credentials.
 */
import express, { type Request, type Response } from 'express';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { DoorkingApiClient } from './client.ts';
import { DoorkingOAuthProvider } from './oauth.ts';
import { createDoorkingMcpServer, type McpPolicy } from './server.ts';

export interface HttpMcpServerOptions {
  apiBaseUrl: string;
  publicIssuerUrl: string;
  defaultGate?: string;
  host?: string;
  allowedHosts?: string[];
  policy: McpPolicy;
}

export function createDoorkingHttpApp(opts: HttpMcpServerOptions) {
  const issuerUrl = new URL(opts.publicIssuerUrl.replace(/\/+$/, ''));
  const mcpResourceUrl = new URL('/mcp', issuerUrl);
  const scopesSupported = opts.policy.allowWorkingCopyWrites
    ? ['doorking:read', 'doorking:stage']
    : ['doorking:read'];

  const app = createMcpExpressApp({
    host: opts.host || '127.0.0.1',
    ...(opts.allowedHosts?.length ? { allowedHosts: opts.allowedHosts } : {}),
  });
  app.set('trust proxy', 1);

  const provider = new DoorkingOAuthProvider({
    apiBaseUrl: opts.apiBaseUrl,
    defaultGate: opts.defaultGate,
    allowWorkingCopyWrites: opts.policy.allowWorkingCopyWrites,
  });

  // Official MCP OAuth 2.1 router: /.well-known/oauth-authorization-server,
  // /.well-known/oauth-protected-resource/mcp, /authorize, /token, /register, /revoke.
  app.use(mcpAuthRouter({
    provider,
    issuerUrl,
    resourceServerUrl: mcpResourceUrl,
    scopesSupported,
    resourceName: 'DoorKing Gate Manager MCP',
  }));

  // Consent page (checks existing same-origin DoorKing session cookie + offers Passkey & SSO) and form submission.
  app.get('/oauth/consent/:id', (req, res) => {
    void provider.renderConsentRequest(req, res);
  });
  app.post('/oauth/approve', express.urlencoded({ extended: false }), (req, res) => {
    void provider.handleConsentSubmit(req, res);
  });

  app.get('/mcp/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'doorking-mcp',
      transport: 'streamable-http',
      oauthIssuer: issuerUrl.toString(),
    });
  });

  const bearerAuth = requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpResourceUrl),
  });

  const handleMcp = async (req: Request, res: Response) => {
    const auth = req.auth;
    if (!auth) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const effectivePolicy: McpPolicy = {
      allowWorkingCopyWrites: opts.policy.allowWorkingCopyWrites && auth.scopes.includes('doorking:stage'),
      allowPhysical: opts.policy.allowPhysical && auth.scopes.includes('doorking:stage'),
    };
    const defaultGate = typeof auth.extra?.gatePhone === 'string' && auth.extra.gatePhone
      ? auth.extra.gatePhone
      : opts.defaultGate;
    const client = new DoorkingApiClient({
      baseUrl: opts.apiBaseUrl,
      token: auth.token,
      defaultGate,
    });
    const mcpServer = createDoorkingMcpServer(client, effectivePolicy);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      void transport.close();
      void mcpServer.close();
    });
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  };

  app.post('/mcp', bearerAuth, (req, res) => { void handleMcp(req, res); });
  app.get('/mcp', bearerAuth, (_req, res) => {
    res.status(405).json({ error: 'Use POST /mcp for stateless Streamable HTTP MCP requests.' });
  });
  app.delete('/mcp', bearerAuth, (_req, res) => {
    res.status(200).json({ ok: true });
  });

  return { app, provider };
}

function boolEnv(name: string, fallback = false): boolean {
  const raw = (process.env[name] || '').trim().toLowerCase();
  if (!raw) return fallback;
  return raw === '1' || raw === 'true' || raw === 'yes';
}

// Only bind a TCP port when executed directly (`node src/http.ts`).
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.MCP_PORT || 8081);
  const host = process.env.MCP_HOST || '127.0.0.1';
  const apiBaseUrl = process.env.DOORKING_API_URL || 'http://127.0.0.1:8080';
  const publicIssuerUrl = process.env.MCP_PUBLIC_URL || `http://127.0.0.1:${port}`;
  const allowedHosts = (process.env.MCP_ALLOWED_HOSTS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const { app } = createDoorkingHttpApp({
    apiBaseUrl,
    publicIssuerUrl,
    defaultGate: process.env.DOORKING_DEFAULT_GATE || '',
    host,
    allowedHosts,
    policy: {
      allowWorkingCopyWrites: boolEnv('DOORKING_ALLOW_WRITES', false),
      allowPhysical: boolEnv('DOORKING_ALLOW_PHYSICAL', false),
    },
  });

  app.listen(port, host, () => {
    console.error(`doorking-mcp Streamable HTTP listening on http://${host}:${port}/mcp (issuer ${publicIssuerUrl}, api ${apiBaseUrl})`);
  });
}
