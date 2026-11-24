import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { DoorkingApiClient, hashSendPreview, type SendPreview } from '../src/client.ts';
import { createDoorkingMcpServer, type McpPolicy } from '../src/server.ts';

interface MockApiState {
  lastAuth: string;
  calls: Array<{ method: string; url: string; body: unknown }>;
  preview: SendPreview;
}

async function withMockApi(
  policy: McpPolicy,
  fn: (ctx: { mcp: Client; state: MockApiState }) => Promise<void>,
) {
  const state: MockApiState = {
    lastAuth: '',
    calls: [],
    preview: {
      changedBlocks: { 'names.bin': [1] },
      residentCounts: [1, 0],
      changes: [{ key: '101', label: '101 Smith, J', change: 'changed', fields: [{ field: 'Name', from: 'Smith, J', to: 'Smith, Jane' }] }],
    },
  };

  const server = http.createServer((req, res) => {
    state.lastAuth = String(req.headers.authorization || '');
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw ? JSON.parse(raw) : undefined;
      state.calls.push({ method: req.method || 'GET', url: req.url || '/', body });

      const send = (status: number, payload: unknown) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };

      if (req.method === 'GET' && req.url === '/api/gates/5550100') {
        return send(200, { phoneNumber: '5550100', siteName: 'Main Gate', addedAt: '2026-11-01T00:00:00Z', role: 'admin' });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/residents') {
        return send(200, {
          rows: [{
            directoryCode: '101', name: 'Smith, J', type: 'Resident', hidden: false,
            areaCode: '214', areaCodeIndex: 0, phone: '5550142', entryCode: '4829',
            securityLevel: 1, elevatorRef: '', floor: '', cards: ['10234'], entryOffset: 0, recordOffset: 0, note: 'Front',
          }],
          unassignedCards: [], areaCodes: [], emptyCodes: ['102'], dirDigits: 3,
          cache: { exists: true, edited: true, conflicts: [] }, pulled: '2026-11-22T00:00:00Z', saved: '2026-11-22T00:01:00Z', duplicates: [],
        });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/residents/101') {
        return send(200, {
          row: {
            directoryCode: '101', name: 'Smith, J', type: 'Resident', hidden: false,
            areaCode: '214', areaCodeIndex: 0, phone: '5550142', entryCode: '4829',
            securityLevel: 1, elevatorRef: '', floor: '', cards: ['10234'], entryOffset: 0, recordOffset: 0, note: 'Front',
          },
        });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/residents/101/history') {
        return send(200, { changes: [{ id: 'ev1', summary: 'Edited 101' }] });
      }
      if (req.method === 'POST' && req.url === '/api/gates/5550100/residents') {
        return send(201, { changed: { 'names.bin': [1] } });
      }
      if (req.method === 'PUT' && req.url === '/api/gates/5550100/residents/999/note') {
        return send(200, { note: body.note });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/residents/999') {
        return send(200, {
          directoryCode: '999', name: 'Test Vendor', type: 'Vendor', hidden: true,
          areaCode: '', areaCodeIndex: null, phone: '', entryCode: '', securityLevel: 1,
          elevatorRef: '', floor: '', cards: [], entryOffset: 0, recordOffset: 0, note: 'vendor note',
        });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/prefs') {
        return send(200, { relayLabels: { '0': 'Main Entry' } });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/relays') {
        return send(200, { checkedAt: '2026-11-23T00:00:00Z', relays: [{ relay: 0, code: '0', state: 'Off', name: '' }], timers: [] });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/job') {
        return send(200, { state: 'idle', log: [] });
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/send') {
        if (!state.preview.changes?.length) return send(409, { error: 'The working copy has no changes to send.' });
        return send(200, state.preview);
      }
      if (req.method === 'GET' && req.url === '/api/gates/5550100/working-copy') {
        return send(200, { exists: true, edited: Boolean(state.preview.changes?.length), conflicts: [] });
      }
      if (req.method === 'POST' && req.url === '/api/gates/5550100/send') {
        if (body?.confirm !== true) return send(400, { error: 'Send must be confirmed' });
        return send(202, { ok: true, state: 'running' });
      }
      if (req.method === 'PUT' && req.url === '/api/gates/5550100/relays') {
        if (typeof body?.['0'] !== 'boolean') return send(400, { error: 'No relay states given' });
        return send(200, { ok: true, relays: [{ relay: 0, code: '0', state: '0', name: 'Entry' }] });
      }
      return send(404, { error: 'Not found' });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  const client = new DoorkingApiClient({
    baseUrl: `http://127.0.0.1:${port}`,
    token: 'dkg_0123456789ab_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    defaultGate: '5550100',
  });
  const mcpServer = createDoorkingMcpServer(client, policy);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await mcpServer.connect(serverTransport);
  const mcpClient = new Client({ name: 'test-client', version: '1.0.0' });
  await mcpClient.connect(clientTransport);

  try {
    await fn({ mcp: mcpClient, state });
  } finally {
    await mcpClient.close();
    await mcpServer.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('default read-only MCP hides write/physical tools, masks PII in search, and serves resources + prompts', async () => {
  await withMockApi({ allowWorkingCopyWrites: false, allowPhysical: false }, async ({ mcp, state }) => {
    const tools = (await mcp.listTools()).tools.map((t) => t.name);
    assert.ok(tools.includes('search_directory'));
    assert.ok(tools.includes('preview_pending_changes'));
    assert.ok(!tools.includes('list_portal_requests'), 'webOnly portal tool hidden for dkg_ API keys');
    assert.ok(!tools.includes('upsert_directory_entry'), 'Tier 1 write tool hidden in read-only mode');
    assert.ok(!tools.includes('send_to_gate'), 'Tier 2 physical tool hidden in read-only mode');
    assert.ok(!tools.includes('pulse_gate_relay'), 'Tier 2 relay tool hidden in read-only mode');

    // Clean working copy (409 from GET /send) returns hasPendingChanges: false without isError
    state.preview = { changedBlocks: {}, residentCounts: [1, 0], changes: [] };
    const cleanPrev = await mcp.callTool({ name: 'preview_pending_changes', arguments: {} });
    assert.ok(!cleanPrev.isError);
    const cleanJson = JSON.parse((cleanPrev.content as Array<{ text: string }>)[0].text);
    assert.strictEqual(cleanJson.hasPendingChanges, false);
    assert.strictEqual(cleanJson.diffHash, null);

    // Relay status joins human labels from /prefs
    const relayRes = await mcp.callTool({ name: 'get_relay_status', arguments: {} });
    const relayJson = JSON.parse((relayRes.content as Array<{ text: string }>)[0].text);
    assert.strictEqual(relayJson.relays[0].name, 'Main Entry');

    const searchRes = await mcp.callTool({ name: 'search_directory', arguments: { query: 'smith' } });
    const searchJson = JSON.parse((searchRes.content as Array<{ text: string }>)[0].text);
    assert.strictEqual(searchJson.entries[0].entryCodeMasked, '••••');
    assert.strictEqual(searchJson.entries[0].entryCode, undefined);
    assert.strictEqual(searchJson.entries[0].phoneMasked, '•••-•••-0142');
    assert.strictEqual(state.lastAuth, 'Bearer dkg_0123456789ab_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

    const detailRes = await mcp.callTool({ name: 'get_resident_details', arguments: { directoryCode: '101', includeSensitive: true } });
    const detailJson = JSON.parse((detailRes.content as Array<{ text: string }>)[0].text);
    assert.strictEqual(detailJson.entry.entryCode, '4829');
    assert.strictEqual(detailJson.entry.phone, '5550142');
    assert.strictEqual(detailJson.recentChanges.length, 1);

    const summaryResource = await mcp.readResource({ uri: 'doorking://gates/5550100/summary' });
    const summaryJson = JSON.parse((summaryResource.contents[0] as { text: string }).text);
    assert.strictEqual(summaryJson.residentsCount, 1);

    const prompt = await mcp.getPrompt({ name: 'review-before-send', arguments: { phone: '5550100' } });
    assert.ok(prompt.messages[0].content.type === 'text');
    assert.match(prompt.messages[0].content.text, /diffHash/);
  });
});

test('physical mode enforces exact diffHash on send_to_gate and momentary open on pulse_gate_relay', async () => {
  await withMockApi({ allowWorkingCopyWrites: true, allowPhysical: true }, async ({ mcp, state }) => {
    const previewRes = await mcp.callTool({ name: 'preview_pending_changes', arguments: {} });
    const previewJson = JSON.parse((previewRes.content as Array<{ text: string }>)[0].text);
    assert.strictEqual(previewJson.diffHash, hashSendPreview(state.preview));

    // Stale/wrong diffHash must be refused without calling POST /send.
    const badSend = await mcp.callTool({ name: 'send_to_gate', arguments: { expectedDiffHash: 'deadbeef00000000' } });
    assert.strictEqual(badSend.isError, true);
    assert.ok(!state.calls.some((c) => c.method === 'POST' && c.url.endsWith('/send')));

    // Upserting a Vendor with a note sends vendor: true + PUT /note and returns the updated entry
    const upsertRes = await mcp.callTool({
      name: 'upsert_directory_entry',
      arguments: { mode: 'create', directoryCode: '999', name: 'Test Vendor', type: 'Vendor', note: 'vendor note' },
    });
    assert.ok(!upsertRes.isError);
    const postRes = state.calls.find((c) => c.method === 'POST' && c.url.endsWith('/residents'));
    assert.strictEqual((postRes?.body as Record<string, unknown>)?.vendor, true);
    const notePut = state.calls.find((c) => c.method === 'PUT' && c.url.endsWith('/residents/999/note'));
    assert.deepStrictEqual(notePut?.body, { note: 'vendor note' });

    // Exact diffHash succeeds and sends { confirm: true }.
    const goodSend = await mcp.callTool({ name: 'send_to_gate', arguments: { expectedDiffHash: previewJson.diffHash } });
    assert.ok(!goodSend.isError);
    const sendCall = state.calls.find((c) => c.method === 'POST' && c.url.endsWith('/send'));
    assert.deepStrictEqual(sendCall?.body, { confirm: true });

    // Relay pulse sends { "0": true, holdMinutes: 1 } matching PUT /relays contract.
    const pulse = await mcp.callTool({ name: 'pulse_gate_relay', arguments: { relay: 0, reason: 'Delivery driver at main gate' } });
    assert.ok(!pulse.isError);
    const relayCall = state.calls.find((c) => c.method === 'PUT' && c.url.endsWith('/relays'));
    assert.deepStrictEqual(relayCall?.body, { '0': true, holdMinutes: 1 });
  });
});
