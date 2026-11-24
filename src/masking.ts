/**
 * @module masking
 *
 * PII redaction for LLM tool responses and conflict-free 4-digit keypad entry code generation.
 */
import crypto from 'node:crypto';
import type { ResidentRow } from './client.ts';

export function maskEntryCode(code: string | undefined | null): string {
  const clean = String(code ?? '').trim();
  return clean ? '••••' : '';
}

export function maskPhone(areaCode: string | undefined | null, phone: string | undefined | null): string {
  const digits = `${areaCode || ''}${phone || ''}`.replace(/\D/g, '');
  if (!digits) return '';
  if (digits.length <= 4) return '••••';
  return `•••-•••-${digits.slice(-4)}`;
}

export function redactResident(row: ResidentRow, includeSensitive: boolean): Record<string, unknown> {
  const base: Record<string, unknown> = {
    directoryCode: row.directoryCode,
    name: row.name,
    type: row.type,
    hidden: row.hidden,
    securityLevel: row.securityLevel,
    elevatorRef: row.elevatorRef,
    floor: row.floor,
    cards: row.cards,
    note: row.note || '',
    portalEnabled: Boolean(row.portalEnabled),
  };
  if (includeSensitive) {
    base.areaCode = row.areaCode;
    base.phone = row.phone;
    base.entryCode = row.entryCode;
    if (row.email) base.email = row.email;
  } else {
    base.phoneMasked = maskPhone(row.areaCode, row.phone);
    base.hasEntryCode = Boolean(row.entryCode);
    base.entryCodeMasked = maskEntryCode(row.entryCode);
  }
  return base;
}

const WEAK_CODES = new Set(['0001', '1000', '2000', '2580', '0852', '1999', '1230', '4321', '1357', '2468']);

export function isWeakEntryCode(code: string): boolean {
  if (!/^\d{4}$/.test(code)) return true;
  if (WEAK_CODES.has(code)) return true;
  if (code[0] === code[1] && code[1] === code[2] && code[2] === code[3]) return true;
  if (code.slice(0, 2) === code.slice(2)) return true;
  if (code[0] === code[1] && code[2] === code[3]) return true;
  if (code[0] === code[3] && code[1] === code[2]) return true;
  const d = [...code].map(Number);
  const asc = d[1] === d[0] + 1 && d[2] === d[1] + 1 && d[3] === d[2] + 1;
  const desc = d[1] === d[0] - 1 && d[2] === d[1] - 1 && d[3] === d[2] - 1;
  if (asc || desc) return true;
  const n = Number(code);
  return n >= 2000 && n <= 2035;
}

export function generateSafeEntryCode(usedCodes: Iterable<string>): string {
  const taken = new Set<string>();
  for (const raw of usedCodes) {
    const digits = String(raw || '').replace(/\D/g, '');
    if (digits) taken.add(digits.padStart(4, '0'));
  }
  for (let i = 0; i < 500; i++) {
    const candidate = String(crypto.randomInt(0, 10000)).padStart(4, '0');
    if (!taken.has(candidate) && !isWeakEntryCode(candidate)) return candidate;
  }
  for (let n = 0; n < 10000; n++) {
    const candidate = String(n).padStart(4, '0');
    if (!taken.has(candidate) && !isWeakEntryCode(candidate)) return candidate;
  }
  throw new Error('No unused 4-digit entry codes remain.');
}
