import type { ProbeResult } from './probe-result';
import { parseProxyTarget, type ProxyTarget } from './proxy-target';

export type PoolStack = 'v4' | 'v6' | 'v4/v6';

export interface PoolEntry {
  readonly address: string;
  readonly asn: string | null;
  readonly country: string | null;
  readonly stack: PoolStack | null;
  readonly comment: string;
}

export interface PoolLine {
  readonly raw: string;
  readonly entry: PoolEntry | null;
}

export interface PoolMetadata {
  readonly asn?: string;
  readonly country?: string;
  readonly stack?: PoolStack;
}

export function parsePoolText(text: string): PoolLine[] {
  if (!text) return [];
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((raw) => ({ raw, entry: parsePoolEntry(raw) }));
}

export function serializePoolText(lines: readonly PoolLine[]): string {
  return lines.map((line) => line.raw).join('\n');
}

export function parsePoolEntry(line: string): PoolEntry | null {
  const raw = line.trim();
  if (!raw || raw.startsWith('#')) return null;

  const commentIndex = raw.indexOf('#');
  const main = (commentIndex >= 0 ? raw.slice(0, commentIndex) : raw).trim();
  const comment = commentIndex >= 0 ? raw.slice(commentIndex).trim() : '';
  const fields = main.split(',').map((field) => field.trim());
  const address = fields[0] ?? '';
  if (!address) return null;

  return {
    address,
    asn: fields[1] || null,
    country: fields[2] || null,
    stack: normalizePoolStack(fields[3]),
    comment,
  };
}

export function formatPoolEntry(entry: PoolEntry): string {
  const address = normalizePoolAddress(entry.address) ?? entry.address.trim();
  const fields = [
    address,
    formatPoolAsn(entry.asn),
    formatPoolCountry(entry.country),
    entry.stack ?? 'null',
  ];
  const comment = normalizeComment(entry.comment);
  return `${fields.join(',')}${comment}`;
}

export function normalizePoolAddress(value: string, defaultPort = 443): string | null {
  return parseProxyTarget(value, defaultPort)?.authority ?? null;
}

export function parsePoolAddress(entry: PoolEntry, defaultPort = 443): ProxyTarget | null {
  return parseProxyTarget(entry.address, defaultPort);
}

export function extractPoolAddressKey(value: string): string {
  return value.split('#', 1)[0]?.split(',')[0]?.trim() ?? '';
}

export function canonicalAddressKey(value: string, defaultPort = 443): string {
  return parseProxyTarget(value, defaultPort)?.key ?? value.trim().toLowerCase();
}

export function poolMetadataFromProbe(result: ProbeResult): PoolMetadata {
  if (result.status !== 'alive') return {};

  const exits = result.exits.length > 0
    ? result.exits
    : result.exitIp
      ? [{ family: result.exitFamily === 'dual' ? 'unknown' as const : result.exitFamily, ip: result.exitIp }]
      : [];
  const asn = joinMetadata(exits.map((exit) => normalizeAsn(exit.asn)));
  const country = joinMetadata(exits.map((exit) => normalizeCountry(exit.country)));
  const stack = inferPoolStack(result.exitFamily, exits.map((exit) => exit.family));

  return {
    ...(asn ? { asn } : {}),
    ...(country ? { country } : {}),
    ...(stack ? { stack } : {}),
  };
}

export function mergePoolMetadata(previous: PoolEntry, metadata: PoolMetadata): PoolEntry {
  return {
    address: normalizePoolAddress(previous.address) ?? previous.address,
    asn: isUnknownMetaValue(metadata.asn) ? previous.asn : formatPoolAsnValue(metadata.asn),
    country: isUnknownMetaValue(metadata.country)
      ? (normalizeCountry(previous.country) ?? previous.country)
      : (normalizeCountry(metadata.country) ?? null),
    stack: metadata.stack ?? previous.stack,
    comment: previous.comment,
  };
}

export function updatePoolEntryFromProbe(previous: PoolEntry, result: ProbeResult): PoolEntry {
  if (result.status !== 'alive') return previous;
  return mergePoolMetadata(previous, poolMetadataFromProbe(result));
}

export function formatPoolAsn(value: string | null | undefined): string {
  if (isUnknownMetaValue(value)) return 'null';
  return String(value)
    .split(/[\/,\s\uFF0C\uFF1B;]+/)
    .map((item) => item.trim().replace(/^AS/i, '').toUpperCase())
    .filter(Boolean)
    .map((item) => `AS${item}`)
    .join('/') || 'null';
}

export function normalizeAsn(value: string | null | undefined): string | undefined {
  const text = String(value ?? '').trim().replace(/^AS/i, '').toUpperCase();
  return text && !isUnknownMetaValue(text) ? text : undefined;
}

export function normalizeCountry(value: string | null | undefined): string | undefined {
  const text = String(value ?? '').trim().toUpperCase();
  return text && !isUnknownMetaValue(text) ? text : undefined;
}

export function normalizePoolStack(value: string | null | undefined): PoolStack | null {
  const text = String(value ?? '').trim().toLowerCase().replace(/_/g, '-');
  if (['v4', 'ipv4', 'ipv4-only', 'only-ipv4'].includes(text)) return 'v4';
  if (['v6', 'ipv6', 'ipv6-only', 'only-ipv6'].includes(text)) return 'v6';
  if (['v4/v6', 'v6/v4', 'dual', 'dual-stack', 'both', 'all', 'ipv4-ipv6'].includes(text)) return 'v4/v6';
  return null;
}

export function isUnknownMetaValue(value: unknown): boolean {
  const text = String(value ?? '').trim().toLowerCase();
  return !text || ['null', 'unknown', 'n/a', '-', 'asnull', 'asunknown'].includes(text);
}

function formatPoolAsnValue(value: string | undefined): string | null {
  const formatted = formatPoolAsn(value);
  return formatted === 'null' ? null : formatted;
}

function formatPoolCountry(value: string | null | undefined): string {
  return normalizeCountry(value) ?? 'null';
}

function normalizeComment(value: string): string {
  const comment = value.trim();
  if (!comment) return '';
  return comment.startsWith('#') ? ` ${comment}` : ` #${comment}`;
}

function joinMetadata(values: readonly (string | undefined)[]): string | undefined {
  const unique = [...new Set(values.filter((value): value is string => Boolean(value)))];
  return unique.length ? unique.join('/') : undefined;
}

function inferPoolStack(
  family: ProbeResult['exitFamily'],
  exitFamilies: readonly ('ipv4' | 'ipv6' | 'unknown')[],
): PoolStack | undefined {
  const hasIpv4 = family === 'ipv4' || family === 'dual' || exitFamilies.includes('ipv4');
  const hasIpv6 = family === 'ipv6' || family === 'dual' || exitFamilies.includes('ipv6');
  if (hasIpv4 && hasIpv6) return 'v4/v6';
  if (hasIpv4) return 'v4';
  if (hasIpv6) return 'v6';
  return undefined;
}

/** 合并同一地址的池条目：新条目的已知元数据和备注优先，缺失字段沿用旧值。 */
export function mergePoolEntry(previous: PoolEntry, next: PoolEntry): PoolEntry {
  const normalizedAddress = normalizePoolAddress(next.address) ?? previous.address;
  const metadata: PoolMetadata = {
    ...(!isUnknownMetaValue(next.asn) && next.asn ? { asn: next.asn } : {}),
    ...(!isUnknownMetaValue(next.country) && next.country ? { country: next.country } : {}),
    ...(next.stack ? { stack: next.stack } : {}),
  };
  const merged = mergePoolMetadata({ ...previous, address: normalizedAddress }, metadata);
  return { ...merged, comment: next.comment || previous.comment };
}
