/**
 * @module server
 *
 * DoorKing MCP Server: registers Tier 0 (read-only), optional Tier 1 (working-copy staging), and optional Tier 2
 * (guarded physical gate) tools, read-only resources, and guided prompts — all strictly backed by the REST API.
 */
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import * as z from 'zod';
import {
  DoorkingApiClient,
  DoorkingApiError,
  hashSendPreview,
  type DataReply,
  type HistoryEvent,
  type Job,
  type Relay,
  type ResidentRow,
  type ResidentsReply,
  type Schedule,
  type SendPreview,
  type SettingsReply,
} from './client.ts';
import { generateSafeEntryCode, redactResident } from './masking.ts';

export interface McpPolicy {
  /** Allow Tier 1 reversible working-copy edits, pulls, and portal request reviews (never touches physical board). */
  allowWorkingCopyWrites: boolean;
  /** Allow Tier 2 physical actions (`send_to_gate` with diffHash + momentary `pulse_gate_relay`). Default: false. */
  allowPhysical: boolean;
}

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

function jsonResult(data: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errorResult(err: unknown) {
  const message = err instanceof DoorkingApiError
    ? `DoorKing API error (${err.status}): ${err.message}`
    : err instanceof Error
      ? err.message
      : String(err);
  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: message }],
  };
}

async function runTool<T>(fn: () => Promise<T>) {
  try {
    return jsonResult(await fn());
  } catch (err) {
    return errorResult(err);
  }
}

export function createDoorkingMcpServer(client: DoorkingApiClient, policy: McpPolicy): McpServer {
  const server = new McpServer({
    name: 'doorking-mcp',
    version: '1.0.0',
  });

  const phoneField = z.string().optional().describe('Gate phone number (digits). Optional if DOORKING_DEFAULT_GATE is set or only one gate is accessible.');

  // =========================================================================
  // TIER 0: Read-Only Tools (always enabled)
  // =========================================================================

  server.registerTool('list_gates', {
    title: 'List accessible gates',
    description: 'Lists DoorKing gates accessible with the configured credential, including role and site name.',
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, () => runTool(async () => ({
    gates: await client.listGates(),
    policy: {
      workingCopyWritesEnabled: policy.allowWorkingCopyWrites,
      physicalActionsEnabled: policy.allowPhysical,
    },
  })));

  server.registerTool('get_job_status', {
    title: 'Get DKS Cloud job status',
    description: 'Returns the current or latest DKS Cloud connection job (pull or send), state, timestamps, and log tail.',
    inputSchema: { phone: phoneField },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const job = await client.request<Job>('GET', client.gatePath(p, '/job'));
    return { phone: p, ...job, log: (job.log || []).slice(-40) };
  }));

  server.registerTool('search_directory', {
    title: 'Search residents & vendors directory',
    description: 'Searches the gate working copy by name, directory code, card number, phone, or type. Entry codes and phone numbers are masked by default.',
    inputSchema: {
      phone: phoneField,
      query: z.string().optional().describe('Case-insensitive substring matched against name, directory code, card numbers, phone, or note.'),
      kind: z.enum(['all', 'resident', 'vendor']).optional().describe('Filter by entry type (default: all).'),
      securityLevel: z.number().int().min(0).max(31).optional().describe('Filter by DoorKing security level.'),
      limit: z.number().int().min(1).max(MAX_LIMIT).optional().describe(`Max results to return (default ${DEFAULT_LIMIT}, max ${MAX_LIMIT}).`),
      offset: z.number().int().min(0).optional().describe('Pagination offset (default 0).'),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, query, kind, securityLevel, limit, offset }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<ResidentsReply>('GET', client.gatePath(p, '/residents'));
    const q = (query || '').trim().toLowerCase();
    const filtered = (data.rows || []).filter((r) => {
      if (kind === 'resident' && r.type !== 'Resident') return false;
      if (kind === 'vendor' && r.type !== 'Vendor') return false;
      if (securityLevel !== undefined && Number(r.securityLevel) !== securityLevel) return false;
      if (!q) return true;
      return (
        (r.name || '').toLowerCase().includes(q)
        || (r.directoryCode || '').toLowerCase().includes(q)
        || (r.note || '').toLowerCase().includes(q)
        || (r.phone || '').includes(q)
        || (r.cards || []).some((c) => c.includes(q))
      );
    });
    const start = offset ?? 0;
    const pageSize = Math.min(limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    return {
      phone: p,
      totalMatches: filtered.length,
      offset: start,
      limit: pageSize,
      hasMore: start + pageSize < filtered.length,
      edited: Boolean(data.cache?.edited),
      conflictCount: data.cache?.conflicts?.length || 0,
      duplicateCount: data.duplicates?.length || 0,
      entries: filtered.slice(start, start + pageSize).map((r) => redactResident(r, false)),
    };
  }));

  server.registerTool('get_resident_details', {
    title: 'Get resident or vendor details',
    description: 'Fetches a single directory entry and its recent change history. Set includeSensitive=true only when full phone/entryCode is required.',
    inputSchema: {
      phone: phoneField,
      directoryCode: z.string().min(1).describe('Directory code (e.g. "101" or "0101").'),
      includeSensitive: z.boolean().optional().describe('When true, returns unmasked phone number, entry code, and email. Default: false.'),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, directoryCode, includeSensitive }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const code = encodeURIComponent(directoryCode.trim());
    const [entry, hist] = await Promise.all([
      client.request<{ row?: ResidentRow } & ResidentRow>('GET', client.gatePath(p, `/residents/${code}`)),
      client.request<{ changes?: unknown[] }>('GET', client.gatePath(p, `/residents/${code}/history`)).catch(() => ({ changes: [] })),
    ]);
    const row = entry.row || entry;
    return {
      phone: p,
      entry: redactResident(row, Boolean(includeSensitive)),
      recentChanges: (hist.changes || []).slice(0, 10),
    };
  }));

  server.registerTool('generate_safe_entry_code', {
    title: 'Generate safe 4-digit entry code',
    description: 'Reads existing entry and directory codes from the gate working copy and generates a non-colliding, non-weak 4-digit keypad entry code.',
    inputSchema: { phone: phoneField },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, ({ phone }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<ResidentsReply>('GET', client.gatePath(p, '/residents'));
    const used: string[] = [];
    for (const r of data.rows || []) {
      if (r.entryCode) used.push(r.entryCode);
      if (r.directoryCode) used.push(r.directoryCode);
    }
    return { phone: p, suggestedEntryCode: generateSafeEntryCode(used) };
  }));

  server.registerTool('query_transactions', {
    title: 'Query gate transactions',
    description: 'Queries gate access transactions with filters (search, eventType, access, directoryCode, date range) and strict pagination.',
    inputSchema: {
      phone: phoneField,
      search: z.string().optional().describe('Substring match against name, directory code, number, or event type.'),
      eventType: z.string().optional().describe('Exact or partial eventType filter (e.g. "Cards", "Entry Code", "Directory").'),
      access: z.string().optional().describe('Access result filter (e.g. "Admit", "Deny").'),
      directoryCode: z.string().optional().describe('Filter transactions for a specific directory code.'),
      dateFrom: z.string().optional().describe('Inclusive start date YYYY-MM-DD.'),
      dateTo: z.string().optional().describe('Inclusive end date YYYY-MM-DD.'),
      before: z.number().int().optional().describe('Cursor timestamp (`next` from previous response) for older server pages.'),
      limit: z.number().int().min(1).max(MAX_LIMIT).optional().describe(`Max rows returned (default ${DEFAULT_LIMIT}, max ${MAX_LIMIT}).`),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, search, eventType, access, directoryCode, dateFrom, dateTo, before, limit }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const hasFilter = Boolean(search || eventType || access || directoryCode || dateFrom || dateTo);
    const cap = Math.min(limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    const params = new URLSearchParams();
    params.set('limit', String(hasFilter ? 2000 : cap));
    if (before) params.set('before', String(before));
    const data = await client.request<DataReply>('GET', client.gatePath(p, `/data?${params.toString()}`));
    const tx = data.transactions;
    if (!tx) return { phone: p, updated: null, totalMatches: 0, rows: [], nextCursor: null };
    const q = (search || '').trim().toLowerCase();
    const ev = (eventType || '').trim().toLowerCase();
    const acc = (access || '').trim().toLowerCase();
    const dc = (directoryCode || '').trim().replace(/^0+/, '');
    const filtered = (tx.rows || []).filter((r) => {
      if (ev && !(r.eventType || '').toLowerCase().includes(ev)) return false;
      if (acc && !(r.access || '').toLowerCase().includes(acc)) return false;
      if (dc && (r.directoryCode || '').replace(/^0+/, '') !== dc) return false;
      if (dateFrom && (r.date || '') < dateFrom) return false;
      if (dateTo && (r.date || '') > dateTo) return false;
      if (q && !(
        (r.name || '').toLowerCase().includes(q)
        || (r.directoryCode || '').toLowerCase().includes(q)
        || String(r.number || '').toLowerCase().includes(q)
        || (r.eventType || '').toLowerCase().includes(q)
      )) return false;
      return true;
    });
    return {
      phone: p,
      updated: tx.updated,
      totalMatches: filtered.length,
      nextCursor: tx.next ?? null,
      rows: filtered.slice(0, cap).map((r) => ({
        ts: r.ts,
        date: r.date,
        time: r.time,
        minute: r.minute,
        eventType: r.eventType,
        access: r.access,
        name: r.name,
        directoryCode: r.directoryCode,
        relay: r.relay,
        number: r.lookup === 'entryCode' ? '••••' : r.number,
        hasCameraEligibility: r.camera,
      })),
    };
  }));

  server.registerTool('get_access_insights', {
    title: 'Get access insights & audit summary',
    description: 'Returns gate traffic stats, dormant credentials, unknown cards, and high-frequency/off-hours entry code usage.',
    inputSchema: {
      phone: phoneField,
      days: z.number().int().min(1).max(730).optional().describe('Lookback window in days (1-730, default 30).'),
      limitPerSection: z.number().int().min(1).max(50).optional().describe('Max dormant/unknown/code items per section (default 20).'),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, days, limitPerSection }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const qs = days ? `?days=${days}` : '';
    const audit = await client.request<{
      days: number;
      dormant: Array<Record<string, unknown>>;
      unknownCards: Array<Record<string, unknown>>;
      entryCodes: Array<Record<string, unknown>>;
      traffic: Record<string, unknown>;
    }>('GET', client.gatePath(p, `/audit${qs}`));
    const cap = limitPerSection ?? 20;
    return {
      phone: p,
      days: audit.days,
      traffic: audit.traffic,
      dormantCount: audit.dormant.length,
      dormant: audit.dormant.slice(0, cap).map((d) => ({ ...d, entryCode: d.entryCode ? '••••' : '' })),
      unknownCardsCount: audit.unknownCards.length,
      unknownCards: audit.unknownCards.slice(0, cap),
      entryCodesCount: audit.entryCodes.length,
      entryCodes: audit.entryCodes.slice(0, cap).map((c) => ({ ...c, entryCode: '••••' })),
    };
  }));

  server.registerTool('get_transaction_media_info', {
    title: 'Check snapshot/video media for a minute',
    description: 'Checks whether saved camera snapshots or clips exist for a transaction minute (YYYYMMDD-HHMM). Returns metadata and API paths only.',
    inputSchema: {
      phone: phoneField,
      minute: z.string().regex(/^\d{8}-\d{4}$/, 'Must be YYYYMMDD-HHMM').describe('Transaction minute key (YYYYMMDD-HHMM).'),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, minute }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<{ snapshots: Record<string, { status: string; files: string[]; error: string | null; at: string }> }>('GET', client.gatePath(p, '/snapshots'));
    const entry = data.snapshots?.[minute];
    if (!entry) return { phone: p, minute, available: false, files: [] };
    return {
      phone: p,
      minute,
      available: (entry.files || []).length > 0,
      status: entry.status,
      at: entry.at,
      error: entry.error,
      files: (entry.files || []).map((file) => ({
        file,
        apiPath: client.gatePath(p, `/snapshots/${encodeURIComponent(minute)}/${encodeURIComponent(file)}`),
      })),
    };
  }));

  server.registerTool('preview_pending_changes', {
    title: 'Preview unsent working-copy changes',
    description: 'Returns the exact human-readable diff between the local working copy and the last gate pull, plus a `diffHash` required by `send_to_gate`. Returns `hasPendingChanges: false` when clean.',
    inputSchema: { phone: phoneField },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const status = await client.request<Record<string, unknown>>('GET', client.gatePath(p, '/working-copy'));
    try {
      const preview = await client.request<SendPreview>('GET', client.gatePath(p, '/send'));
      return {
        phone: p,
        hasPendingChanges: true,
        diffHash: hashSendPreview(preview),
        changeCount: preview.changes?.length ?? Object.values(preview.changedBlocks || {}).reduce((n, b) => n + b.length, 0),
        changes: preview.changes || [],
        changedBlocks: preview.changedBlocks || {},
        workingCopy: status,
      };
    } catch (err) {
      if (err instanceof DoorkingApiError && err.status === 409) {
        return {
          phone: p,
          hasPendingChanges: false,
          diffHash: null,
          changeCount: 0,
          changes: [],
          changedBlocks: {},
          workingCopy: status,
          message: err.message,
        };
      }
      throw err;
    }
  }));

  server.registerTool('get_board_settings', {
    title: 'Get board settings',
    description: 'Reads DoorKing board settings (working copy vs last pulled gate value), optionally filtered by group.',
    inputSchema: {
      phone: phoneField,
      group: z.string().optional().describe('Optional group filter (e.g. "Facility", "Holidays", "Security", "Hold Open", "Display", "APB", "System").'),
      onlyModified: z.boolean().optional().describe('If true, return only settings whose working-copy value differs from the last gate pull.'),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, group, onlyModified }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<SettingsReply>('GET', client.gatePath(p, '/settings'));
    const g = (group || '').trim().toLowerCase();
    const fields = (data.fields || []).filter((f) => {
      if (g && !(f.group || '').toLowerCase().includes(g)) return false;
      if (onlyModified && f.value === f.gate) return false;
      return true;
    });
    return {
      phone: p,
      pulled: data.pulled,
      saved: data.saved,
      count: fields.length,
      fields: fields.map((f) => ({
        key: f.key,
        group: f.group,
        name: f.name,
        value: f.secret ? '••••' : f.value,
        gate: f.secret ? '••••' : f.gate,
        modified: f.value !== f.gate,
        editable: f.editable,
      })),
    };
  }));

  server.registerTool('list_schedules', {
    title: 'List scheduled transfers',
    description: 'Lists recurring automatic pull/send/snapshot transfer schedules for the gate.',
    inputSchema: { phone: phoneField },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<{ schedules: Schedule[] }>('GET', client.gatePath(p, '/schedules'));
    return { phone: p, schedules: data.schedules || [] };
  }));

  server.registerTool('get_change_history', {
    title: 'Get gate change history',
    description: 'Returns the newest change/audit events for the gate (who changed what and when).',
    inputSchema: {
      phone: phoneField,
      limit: z.number().int().min(1).max(MAX_LIMIT).optional().describe(`Max events to return (default ${DEFAULT_LIMIT}).`),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone, limit }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<{ events: HistoryEvent[] }>('GET', client.gatePath(p, '/history'));
    const cap = Math.min(limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    return { phone: p, total: (data.events || []).length, events: (data.events || []).slice(0, cap) };
  }));

  server.registerTool('list_past_pulls', {
    title: 'List archived past gate pulls',
    description: 'Lists archived snapshots of previous gate pulls available for comparison or restore.',
    inputSchema: { phone: phoneField },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  }, ({ phone }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const data = await client.request<{ pulls: unknown[] }>('GET', client.gatePath(p, '/pull-archive'));
    return { phone: p, pulls: data.pulls || [] };
  }));

  server.registerTool('get_relay_status', {
    title: 'Get live relay states',
    description: 'Reads live DoorKing relay states (with configured relay labels) and any active auto-release timers.',
    inputSchema: { phone: phoneField },
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, ({ phone }) => runTool(async () => {
    const p = await client.resolveGate(phone);
    const [data, prefs] = await Promise.all([
      client.request<{ checkedAt?: string; relays: Relay[]; timers?: unknown[] }>('GET', client.gatePath(p, '/relays')),
      client.request<{ relayLabels?: Record<string, string> }>('GET', client.gatePath(p, '/prefs')).catch(() => ({ relayLabels: {} })),
    ]);
    const labels: Record<string, string> = prefs.relayLabels || {};
    return {
      phone: p,
      checkedAt: data.checkedAt,
      relays: (data.relays || []).map((r) => ({ ...r, name: r.name || labels[String(r.relay)] || '' })),
      timers: data.timers || [],
    };
  }));

  if (!client.isGateApiKey) {
    server.registerTool('list_portal_requests', {
      title: 'List resident portal change requests',
      description: 'Lists resident self-service change requests (available on user OAuth/bearer sessions).',
      inputSchema: {
        phone: phoneField,
        status: z.enum(['all', 'pending', 'approved', 'rejected']).optional().describe('Filter by request status (default: pending).'),
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    }, ({ phone, status }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const data = await client.request<{ requests: Array<{ status: string }> }>('GET', client.gatePath(p, '/resident-requests'));
      const want = status || 'pending';
      const rows = want === 'all' ? (data.requests || []) : (data.requests || []).filter((r) => r.status === want);
      return { phone: p, status: want, count: rows.length, requests: rows.slice(0, MAX_LIMIT) };
    }));
  }

  // =========================================================================
  // TIER 1: Reversible Working-Copy Staging Tools (opt-in)
  // =========================================================================

  if (policy.allowWorkingCopyWrites) {
    server.registerTool('upsert_directory_entry', {
      title: 'Stage resident or vendor in working copy',
      description: 'Creates or updates a resident/vendor in the LOCAL WORKING COPY only (including optional local note). Does NOT send to the physical gate.',
      inputSchema: {
        phone: phoneField,
        mode: z.enum(['create', 'update']).describe('"create" adds a new directory code; "update" modifies an existing code.'),
        directoryCode: z.string().min(1).describe('Directory code (e.g. "101").'),
        name: z.string().max(15).optional().describe('Display name (max 15 printable ASCII chars).'),
        type: z.enum(['Resident', 'Vendor']).optional().describe('Entry kind (used when creating a new entry).'),
        hidden: z.boolean().optional().describe('Hide from entry-panel directory.'),
        areaCode: z.string().max(4).optional().describe('3- or 4-digit area code.'),
        phoneNumber: z.string().max(7).optional().describe('7-digit local phone number.'),
        entryCode: z.string().max(4).optional().describe('4-digit keypad entry code (or empty string to clear).'),
        securityLevel: z.number().int().min(0).max(31).optional().describe('Security level (0-31).'),
        cards: z.array(z.string()).max(25).optional().describe('Assigned card/remote numbers (up to 25).'),
        note: z.string().max(500).optional().describe('Local management note (saved separately via /note; never sent to gate).'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    }, ({ phone, mode, directoryCode, phoneNumber, type, note, ...fields }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const code = directoryCode.trim();
      const payload: Record<string, unknown> = { ...fields };
      if (phoneNumber !== undefined) payload.phone = phoneNumber;
      let res: Record<string, unknown>;
      if (mode === 'create') {
        payload.directoryCode = code;
        if (type === 'Vendor') payload.vendor = true;
        res = await client.request<Record<string, unknown>>('POST', client.gatePath(p, '/residents'), payload);
      } else {
        res = await client.request<Record<string, unknown>>(
          'PUT',
          client.gatePath(p, `/residents/${encodeURIComponent(code)}`),
          payload,
        );
      }
      if (note !== undefined) {
        await client.request<Record<string, unknown>>(
          'PUT',
          client.gatePath(p, `/residents/${encodeURIComponent(code)}/note`),
          { note },
        );
      }
      const updated = await client.request<{ row?: ResidentRow } & ResidentRow>(
        'GET',
        client.gatePath(p, `/residents/${encodeURIComponent(code)}`),
      ).catch(() => null);
      return {
        phone: p,
        staged: true,
        action: mode === 'create' ? 'created' : 'updated',
        directoryCode: code,
        ...(updated ? { entry: redactResident(updated.row || updated, false) } : {}),
        changed: res.changed ?? null,
      };
    }));

    server.registerTool('delete_directory_entry', {
      title: 'Delete directory entry from working copy',
      description: 'Clears a resident/vendor from the LOCAL WORKING COPY only (reversible until Send).',
      inputSchema: {
        phone: phoneField,
        directoryCode: z.string().min(1).describe('Directory code to clear in the working copy.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    }, ({ phone, directoryCode }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const res = await client.request<Record<string, unknown>>(
        'DELETE',
        client.gatePath(p, `/residents/${encodeURIComponent(directoryCode.trim())}`),
      );
      return { phone: p, staged: true, action: 'deleted', directoryCode: directoryCode.trim(), response: res };
    }));

    server.registerTool('update_board_setting_draft', {
      title: 'Stage board setting changes in working copy',
      description: 'Stages one or more DoorKing board setting key/value pairs in the LOCAL WORKING COPY only. Does NOT send to the gate.',
      inputSchema: {
        phone: phoneField,
        changes: z.record(z.string(), z.string()).describe('Map of setting keys to new string values (e.g. { "talkTime": "1:30" }).'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    }, ({ phone, changes }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const res = await client.request<Record<string, unknown>>('PUT', client.gatePath(p, '/settings'), changes);
      return { phone: p, staged: true, updatedKeys: Object.keys(changes), response: res };
    }));

    server.registerTool('discard_working_copy_changes', {
      title: 'Discard all unsent working-copy changes',
      description: 'Resets the local working copy back to the last pulled gate state, discarding all unsent edits.',
      inputSchema: { phone: phoneField },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    }, ({ phone }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const res = await client.request<Record<string, unknown>>('DELETE', client.gatePath(p, '/working-copy'));
      return { phone: p, discarded: true, response: res };
    }));

    server.registerTool('start_gate_pull', {
      title: 'Start async pull from DKS Cloud',
      description: 'Starts a read-only pull of residents or transactions from the physical gate via DKS Cloud. Returns immediately; poll `get_job_status` for completion.',
      inputSchema: {
        phone: phoneField,
        what: z.enum(['residents', 'transactions']).describe('What to pull from the gate: "residents" or "transactions".'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    }, ({ phone, what }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const res = await client.request<Record<string, unknown>>('POST', client.gatePath(p, '/pull'), { what });
      return { phone: p, started: true, what, response: res };
    }));

    if (!client.isGateApiKey) {
      server.registerTool('review_portal_request', {
        title: 'Approve or reject a resident portal request',
        description: 'Approves (into working copy) or rejects a resident self-service request (available on user OAuth/bearer sessions).',
        inputSchema: {
          phone: phoneField,
          requestId: z.number().int().positive().describe('Resident request ID.'),
          decision: z.enum(['approve', 'reject']).describe('Whether to approve into the working copy or reject.'),
          note: z.string().max(300).optional().describe('Optional reviewer note sent to the resident.'),
          apply: z.boolean().optional().describe('When approving a structured phone request, apply directly to working copy (default: true).'),
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
      }, ({ phone, requestId, decision, note, apply }) => runTool(async () => {
        const p = await client.resolveGate(phone);
        const res = await client.request<Record<string, unknown>>(
          'POST',
          client.gatePath(p, `/resident-requests/${requestId}/review`),
          {
            decision: decision === 'approve' ? 'approved' : 'rejected',
            reviewNote: note || '',
            apply: apply !== false,
          },
        );
        return { phone: p, requestId, decision, response: res };
      }));
    }
  }

  // =========================================================================
  // TIER 2: Guarded Physical Hardware Actions (explicit opt-in ONLY)
  // =========================================================================

  if (policy.allowPhysical) {
    server.registerTool('send_to_gate', {
      title: 'Send working copy to physical gate',
      description: 'PHYSICAL ACTION: Writes staged working-copy changes to the live DoorKing gate over DKS Cloud. Requires `expectedDiffHash` from `preview_pending_changes` to prevent stale pushes.',
      inputSchema: {
        phone: phoneField,
        expectedDiffHash: z.string().min(8).describe('Exact `diffHash` returned by `preview_pending_changes`.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    }, ({ phone, expectedDiffHash }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const preview = await client.request<SendPreview>('GET', client.gatePath(p, '/send'));
      const actualHash = hashSendPreview(preview);
      if (actualHash !== expectedDiffHash.trim()) {
        throw new Error(`Pending diff changed (expected ${expectedDiffHash}, actual ${actualHash}). Re-run preview_pending_changes and confirm before sending.`);
      }
      const res = await client.request<Record<string, unknown>>('POST', client.gatePath(p, '/send'), { confirm: true });
      return { phone: p, sent: true, diffHash: actualHash, response: res };
    }));

    server.registerTool('pulse_gate_relay', {
      title: 'Timed open or release of a gate relay',
      description: 'PHYSICAL ACTION: Opens a gate relay with a mandatory short auto-release timer (1-15 min; indefinite hold is disallowed over MCP) or releases it immediately. Requires an audit reason.',
      inputSchema: {
        phone: phoneField,
        relay: z.number().int().min(0).max(18).describe('Relay index (0 = main entry gate).'),
        state: z.enum(['open', 'release']).optional().describe('"open" holds open with auto-release timer; "release" closes immediately (default: "open").'),
        holdMinutes: z.number().int().min(1).max(15).optional().describe('Auto-release timer in minutes when state="open" (1-15, default 1).'),
        reason: z.string().min(3).max(200).describe('Human-readable reason for the relay action.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    }, ({ phone, relay, state, holdMinutes, reason }) => runTool(async () => {
      const p = await client.resolveGate(phone);
      const isRelease = state === 'release';
      const payload: Record<string, unknown> = { [String(relay)]: !isRelease };
      if (!isRelease) payload.holdMinutes = holdMinutes ?? 1;
      const res = await client.request<Record<string, unknown>>('PUT', client.gatePath(p, '/relays'), payload);
      return { phone: p, relay, state: isRelease ? 'release' : 'open', ...(isRelease ? {} : { holdMinutes: holdMinutes ?? 1 }), reason: reason.trim(), response: res };
    }));
  }

  // =========================================================================
  // Read-Only MCP Resources
  // =========================================================================

  server.registerResource('gates-list', 'doorking://gates', {
    title: 'DoorKing Gates',
    description: 'Accessible DoorKing gates and roles.',
    mimeType: 'application/json',
  }, async (uri) => ({
    contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(await client.listGates(), null, 2) }],
  }));

  server.registerResource('gate-summary', new ResourceTemplate('doorking://gates/{phone}/summary', { list: undefined }), {
    title: 'Gate Summary',
    description: 'High-level status: resident/vendor counts, unsent edits, conflicts, and job state.',
    mimeType: 'application/json',
  }, async (uri, vars) => {
    const p = await client.resolveGate(String(vars.phone || ''));
    const [gate, residents, job] = await Promise.all([
      client.request<Record<string, unknown>>('GET', client.gatePath(p)),
      client.request<ResidentsReply>('GET', client.gatePath(p, '/residents')),
      client.request<Job>('GET', client.gatePath(p, '/job')),
    ]);
    const rows = residents.rows || [];
    const summary = {
      gate,
      residentsCount: rows.filter((r) => r.type === 'Resident').length,
      vendorsCount: rows.filter((r) => r.type === 'Vendor').length,
      edited: Boolean(residents.cache?.edited),
      conflictCount: residents.cache?.conflicts?.length || 0,
      duplicateCount: residents.duplicates?.length || 0,
      pulledAt: residents.pulled,
      jobState: job.state,
    };
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(summary, null, 2) }] };
  });

  server.registerResource('gate-pending-diff', new ResourceTemplate('doorking://gates/{phone}/pending-diff', { list: undefined }), {
    title: 'Pending Gate Diff',
    description: 'Unsent working-copy changes and diffHash for the gate.',
    mimeType: 'application/json',
  }, async (uri, vars) => {
    const p = await client.resolveGate(String(vars.phone || ''));
    try {
      const preview = await client.request<SendPreview>('GET', client.gatePath(p, '/send'));
      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify({ hasPendingChanges: true, diffHash: hashSendPreview(preview), ...preview }, null, 2),
        }],
      };
    } catch (err) {
      if (err instanceof DoorkingApiError && err.status === 409) {
        return {
          contents: [{
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify({ hasPendingChanges: false, diffHash: null, changes: [], changedBlocks: {}, message: err.message }, null, 2),
          }],
        };
      }
      throw err;
    }
  });

  server.registerResource('gate-recent-transactions', new ResourceTemplate('doorking://gates/{phone}/transactions/recent', { list: undefined }), {
    title: 'Recent Gate Transactions',
    description: 'Latest 50 gate access transactions (entry codes masked).',
    mimeType: 'application/json',
  }, async (uri, vars) => {
    const p = await client.resolveGate(String(vars.phone || ''));
    const data = await client.request<DataReply>('GET', client.gatePath(p, '/data'));
    const rows = (data.transactions?.rows || []).slice(0, 50).map((r) => ({
      ...r,
      number: r.lookup === 'entryCode' ? '••••' : r.number,
    }));
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ updated: data.transactions?.updated || null, rows }, null, 2) }] };
  });

  server.registerResource('gate-settings', new ResourceTemplate('doorking://gates/{phone}/settings', { list: undefined }), {
    title: 'Gate Board Settings',
    description: 'DoorKing board settings (secret values masked).',
    mimeType: 'application/json',
  }, async (uri, vars) => {
    const p = await client.resolveGate(String(vars.phone || ''));
    const data = await client.request<SettingsReply>('GET', client.gatePath(p, '/settings'));
    const fields = (data.fields || []).map((f) => ({
      key: f.key,
      group: f.group,
      name: f.name,
      value: f.secret ? '••••' : f.value,
      gate: f.secret ? '••••' : f.gate,
      modified: f.value !== f.gate,
    }));
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ pulled: data.pulled, fields }, null, 2) }] };
  });

  // =========================================================================
  // Guided MCP Prompts
  // =========================================================================

  server.registerPrompt('onboard-resident', {
    title: 'Onboard a new resident',
    description: 'Guides collecting resident info, generating a safe 4-digit code, staging in the working copy, and preparing a diff for human Send.',
    argsSchema: {
      phone: z.string().optional().describe('Gate phone number.'),
      residentName: z.string().describe('Resident display name (max 15 ASCII chars).'),
      unitOrCode: z.string().describe('Target directory code / unit number.'),
    },
  }, ({ phone, residentName, unitOrCode }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: [
          `Onboard resident "${residentName}" into directory code "${unitOrCode}"${phone ? ` on gate ${phone}` : ''}.`,
          '1. Call search_directory to confirm the directory code is free and check existing residents.',
          '2. Call generate_safe_entry_code to obtain a conflict-free 4-digit keypad entry code.',
          '3. If working-copy writes are enabled, stage the entry via upsert_directory_entry (NEVER call send_to_gate without explicit human confirmation).',
          '4. Call preview_pending_changes and present the exact diff checklist to the operator.',
        ].join('\n'),
      },
    }],
  }));

  server.registerPrompt('audit-dormant-access', {
    title: 'Audit dormant credentials & unknown cards',
    description: 'Reviews dormant residents/vendors, unknown cards, and flagged entry codes without making destructive changes.',
    argsSchema: {
      phone: z.string().optional().describe('Gate phone number.'),
      days: z.string().optional().describe('Lookback window in days (default 60).'),
    },
  }, ({ phone, days }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: [
          `Run a read-only access audit${phone ? ` for gate ${phone}` : ''} over the last ${days || '60'} days.`,
          '1. Call get_access_insights with the requested day window.',
          '2. Summarize traffic volume, dormant credentials, unknown card numbers, and flagged/off-hours entry codes.',
          '3. Propose a prioritized cleanup checklist for management review — do NOT delete any entries automatically.',
        ].join('\n'),
      },
    }],
  }));

  server.registerPrompt('investigate-event', {
    title: 'Investigate a gate access event',
    description: 'Correlates transactions around a date/person/unit with directory details and camera snapshot availability.',
    argsSchema: {
      phone: z.string().optional().describe('Gate phone number.'),
      clue: z.string().describe('Name, directory code, card number, or date/time clue to investigate.'),
    },
  }, ({ phone, clue }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: [
          `Investigate gate activity matching "${clue}"${phone ? ` on gate ${phone}` : ''}.`,
          '1. Call query_transactions with the clue and search_directory to match the resident/vendor.',
          '2. For relevant transaction minutes where hasCameraEligibility is true, call get_transaction_media_info to check if snapshots/clips exist.',
          '3. Produce a concise timeline of events and any anomalies.',
        ].join('\n'),
      },
    }],
  }));

  server.registerPrompt('review-before-send', {
    title: 'Review pending changes before Send',
    description: 'Inspects unsent working-copy changes, flags high-impact edits, and builds a pre-send safety checklist.',
    argsSchema: {
      phone: z.string().optional().describe('Gate phone number.'),
    },
  }, ({ phone }) => ({
    messages: [{
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: [
          `Review all pending working-copy changes${phone ? ` for gate ${phone}` : ''} before sending to hardware.`,
          '1. Call preview_pending_changes and get_job_status.',
          '2. Highlight any deletions, security-level changes, hold-open changes, conflicts, or duplicate codes/cards.',
          '3. Output the diffHash and a clear Go/No-Go checklist for human confirmation.',
        ].join('\n'),
      },
    }],
  }));

  return server;
}
