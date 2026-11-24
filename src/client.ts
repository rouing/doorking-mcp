/**
 * @module client
 *
 * Thin REST API client for DoorKing Gate Manager (`api/`).
 * Never touches PostgreSQL, config files, or DKS Cloud directly — every operation is an authenticated HTTP call.
 */
import crypto from 'node:crypto';
import type {
  GateInfo as OaGateInfo,
  HistoryEvent as OaHistoryEvent,
  Job as OaJob,
  Relay as OaRelay,
  Resident as OaResident,
  ResidentsReply as OaResidentsReply,
  Schedule as OaSchedule,
  SettingField as OaSettingField,
  SettingsReply as OaSettingsReply,
  Transaction as OaTransaction,
} from './generated/models/index.ts';

export type GateInfo = OaGateInfo;
export type ResidentRow = OaResident & {
  email?: string;
  portalEnabled?: boolean;
  portalInvited?: boolean;
};
export type ResidentsReply = OaResidentsReply;
export type TransactionRow = OaTransaction;
export interface DataReply {
  transactions: { updated: string; rows: TransactionRow[]; next?: number | null } | null;
  apbEnabled?: boolean;
}
export type GateSettingRow = OaSettingField;
export type SettingsReply = OaSettingsReply;
export type Job = OaJob;
export type Relay = OaRelay;
export type Schedule = OaSchedule;
export type HistoryEvent = OaHistoryEvent;

export interface SendPreview {
  changedBlocks: Record<string, number[]>;
  residentCounts: number[];
  changes?: Array<{
    key: string;
    label: string;
    change: 'added' | 'removed' | 'changed';
    fields: Array<{ field: string; from: string; to: string }>;
  }>;
}

export class DoorkingApiError extends Error {
  readonly status: number;
  readonly body: Record<string, unknown>;

  constructor(message: string, status: number, body: Record<string, unknown>) {
    super(message);
    this.name = 'DoorkingApiError';
    this.status = status;
    this.body = body;
  }
}

export interface DoorkingClientOptions {
  baseUrl: string;
  token: string;
  defaultGate?: string;
  timeoutMs?: number;
}

export function cleanPhone(phone: string): string {
  return String(phone || '').replace(/\D/g, '');
}

/** Deterministic hash of a SendPreview used to confirm the exact pending diff before `send_to_gate`. */
export function hashSendPreview(preview: SendPreview): string {
  const canonical = JSON.stringify({
    changedBlocks: preview.changedBlocks || {},
    changes: preview.changes || [],
  });
  return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

export class DoorkingApiClient {
  readonly baseUrl: string;
  readonly token: string;
  readonly defaultGate: string;
  readonly timeoutMs: number;

  constructor(opts: DoorkingClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.token = opts.token.trim();
    this.defaultGate = cleanPhone(opts.defaultGate || '');
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    if (!this.baseUrl) throw new Error('DOORKING_API_URL is required');
    if (!this.token) throw new Error('DOORKING_API_KEY or DOORKING_BEARER_TOKEN is required');
  }

  get isGateApiKey(): boolean {
    return this.token.startsWith('dkg_');
  }

  async request<T = Record<string, unknown>>(method: string, urlPath: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers: Record<string, string> = {
        Authorization: `Bearer ${this.token}`,
        Accept: 'application/json',
      };
      if (method !== 'GET') headers['Content-Type'] = 'application/json';
      const res = await fetch(`${this.baseUrl}${urlPath}`, {
        method,
        headers,
        body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
        signal: controller.signal,
      });
      const data = await res.json().catch(() => ({})) as Record<string, unknown>;
      if (!res.ok) {
        const msg = typeof data.error === 'string' ? data.error : `HTTP ${res.status} on ${method} ${urlPath}`;
        throw new DoorkingApiError(msg, res.status, data);
      }
      return data as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private resolvedKeyGate: string | null = null;

  private async resolveApiKeyGate(): Promise<string> {
    if (this.defaultGate) return this.defaultGate;
    if (this.resolvedKeyGate) return this.resolvedKeyGate;
    const info = await this.request<{ phone?: string }>('GET', '/api/key-info');
    if (info.phone) {
      this.resolvedKeyGate = cleanPhone(info.phone);
      return this.resolvedKeyGate;
    }
    throw new Error('Pass the "phone" parameter or set DOORKING_DEFAULT_GATE when using a per-gate API key.');
  }

  async resolveGate(phone?: string): Promise<string> {
    const explicit = cleanPhone(phone || '');
    if (explicit) return explicit;
    if (this.defaultGate) return this.defaultGate;
    if (!this.isGateApiKey) {
      const { gates } = await this.request<{ gates: GateInfo[] }>('GET', '/api/gates');
      if (gates.length === 1) return cleanPhone(gates[0].phoneNumber || '');
      if (gates.length > 1) {
        throw new Error(`Multiple gates available (${gates.map((g) => g.phoneNumber).join(', ')}); pass the "phone" parameter.`);
      }
      throw new Error('No gates are accessible for this account.');
    }
    return this.resolveApiKeyGate();
  }

  gatePath(phone: string, sub = ''): string {
    return `/api/gates/${encodeURIComponent(cleanPhone(phone))}${sub}`;
  }

  async listGates(): Promise<GateInfo[]> {
    if (this.isGateApiKey) {
      const phone = await this.resolveApiKeyGate();
      const gate = await this.request<GateInfo>('GET', this.gatePath(phone));
      return [gate];
    }
    const reply = await this.request<{ gates: GateInfo[] }>('GET', '/api/gates');
    return reply.gates || [];
  }
}
