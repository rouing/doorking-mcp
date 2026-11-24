#!/usr/bin/env node
/**
 * @module index
 *
 * Stdio entrypoint for the DoorKing MCP server.
 * IMPORTANT: Never write to stdout — stdout is reserved for MCP JSON-RPC frames. Log only to stderr.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { DoorkingApiClient } from './client.ts';
import { createDoorkingMcpServer } from './server.ts';

function boolEnv(name: string, fallback = false): boolean {
  const raw = (process.env[name] || '').trim().toLowerCase();
  if (!raw) return fallback;
  return raw === '1' || raw === 'true' || raw === 'yes';
}

const baseUrl = process.env.DOORKING_API_URL || 'http://127.0.0.1:8080';
const token = process.env.DOORKING_API_KEY || process.env.DOORKING_BEARER_TOKEN || '';
const defaultGate = process.env.DOORKING_DEFAULT_GATE || '';

if (!token) {
  console.error('doorking-mcp: set DOORKING_API_KEY (dkg_...) or DOORKING_BEARER_TOKEN (dks_...)');
  process.exit(1);
}

const policy = {
  allowWorkingCopyWrites: boolEnv('DOORKING_ALLOW_WRITES', false),
  allowPhysical: boolEnv('DOORKING_ALLOW_PHYSICAL', false),
};

const client = new DoorkingApiClient({ baseUrl, token, defaultGate });
const server = createDoorkingMcpServer(client, policy);
const transport = new StdioServerTransport();

await server.connect(transport);
console.error(
  `doorking-mcp running on stdio -> ${client.baseUrl} (writes=${policy.allowWorkingCopyWrites}, physical=${policy.allowPhysical})`,
);
