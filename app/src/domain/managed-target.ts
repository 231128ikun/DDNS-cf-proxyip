import { parseProxyTarget } from './proxy-target';
import { isUnknownMetaValue, normalizeAsn, normalizeCountry, type PoolEntry } from './pool-entry';
import type { ProbeResult } from './probe-result';

export type TargetMode = 'A' | 'TXT';
export type ExitFilter = 'any' | 'v4' | 'v6' | 'dual';

export interface ManagedTarget {
  readonly mode: TargetMode;
  readonly domain: string;
  readonly port: number | null;
  readonly minActive: number;
  readonly exitFilter: ExitFilter;
  readonly countries: readonly string[];
  readonly asns: readonly string[];
}

/** 可选字段显式带上 `undefined`：读取旧数据时字段可能整体缺失，调用方无需做条件展开。 */
export interface ManagedTargetInput {
  readonly mode?: string | undefined;
  readonly domain: string;
  readonly port?: number | string | undefined;
  readonly minActive?: number | string | undefined;
  readonly exitFilter?: string | undefined;
  readonly countries?: readonly string[] | string | undefined;
  readonly asns?: readonly string[] | string | undefined;
}

export function normalizeManagedTarget(input: ManagedTargetInput): ManagedTarget | null {
  const mode: TargetMode = String(input.mode ?? 'A').trim().toUpperCase() === 'TXT' ? 'TXT' : 'A';
  const domain = String(input.domain ?? '').trim().replace(/\.$/, '').toLowerCase();
  if (!domain) return null;

  const parsedPort = Number.parseInt(String(input.port ?? 443), 10);
  const port = mode === 'TXT' ? null : Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65_535 ? parsedPort : 443;
  const parsedMinActive = Number.parseInt(String(input.minActive ?? 1), 10);

  return {
    mode,
    domain,
    port,
    minActive: Number.isFinite(parsedMinActive) ? Math.max(0, parsedMinActive) : 1,
    exitFilter: normalizeExitFilter(input.exitFilter),
    countries: normalizeList(input.countries, normalizeCountry),
    asns: normalizeList(input.asns, normalizeAsn),
  };
}

export function normalizeExitFilter(value: string | undefined): ExitFilter {
  const text = String(value ?? '').trim().toLowerCase().replace(/_/g, '-');
  if (!text || ['any', 'all', 'v4/v6', 'v6/v4'].includes(text)) return 'any';
  if (['v4', 'ipv4', 'ipv4-only', 'only-ipv4'].includes(text)) return 'v4';
  if (['v6', 'ipv6', 'ipv6-only', 'only-ipv6'].includes(text)) return 'v6';
  if (['dual', 'dual-stack', 'both'].includes(text)) return 'dual';
  return 'any';
}

export function probeMatchesTarget(result: ProbeResult, target: ManagedTarget): boolean {
  if (result.status !== 'alive') return false;
  if (!exitFilterMatches(result.exitFamily, target.exitFilter)) return false;
  if (target.countries.length && !intersects(target.countries, splitMetadata(result.exits.map((exit) => exit.country)))) return false;
  if (target.asns.length && !intersects(target.asns, splitMetadata(result.exits.map((exit) => exit.asn)).map((asn) => normalizeAsn(asn) ?? ''))) return false;
  return true;
}

export function storedEntryMatchesTarget(entry: PoolEntry, target: ManagedTarget): boolean {
  if (target.countries.length && !isUnknownMetaValue(entry.country)) {
    if (!intersects(target.countries, splitMetadata([entry.country]))) return false;
  }
  if (target.asns.length && !isUnknownMetaValue(entry.asn)) {
    if (!intersects(target.asns, splitMetadata([entry.asn]).map((asn) => normalizeAsn(asn) ?? ''))) return false;
  }
  if (target.exitFilter !== 'any' && !isUnknownMetaValue(entry.stack)) {
    if (!exitFilterMatches(entry.stack ?? 'unknown', target.exitFilter)) return false;
  }
  return true;
}

export function selectCandidateEntries(
  entries: readonly PoolEntry[],
  target: ManagedTarget,
  excludedAddresses: ReadonlySet<string>,
): readonly PoolEntry[] {
  return entries.filter((entry) => {
    const address = parseProxyTarget(entry.address);
    if (!address) return false;
    if (target.mode === 'A' && (!target.port || address.port !== target.port)) return false;
    if (!storedEntryMatchesTarget(entry, target)) return false;
    return !excludedAddresses.has(address.key);
  });
}

export function activeValueForEntry(entry: PoolEntry, target: ManagedTarget): string {
  const parsed = parseProxyTarget(entry.address);
  if (!parsed) return entry.address;
  return target.mode === 'A' ? parsed.host : parsed.authority;
}

export function normalizeList(
  value: readonly string[] | string | undefined,
  normalizer: (item: string | null | undefined) => string | undefined,
): readonly string[] {
  const source = Array.isArray(value) ? value : String(value ?? '').split(/[,;，；\s]+/);
  return [...new Set(source.map((item) => normalizer(String(item).trim())).filter((item): item is string => Boolean(item)))];
}

function exitFilterMatches(family: string, filter: ExitFilter): boolean {
  if (filter === 'any') return true;
  if (filter === 'v4') return family === 'v4' || family === 'ipv4';
  if (filter === 'v6') return family === 'v6' || family === 'ipv6';
  return family === 'v4/v6' || family === 'dual';
}

function splitMetadata(values: readonly (string | null | undefined)[]): readonly string[] {
  return values.flatMap((value) => String(value ?? '').split(/[\/,;，；\s]+/).map((item) => item.trim()).filter(Boolean));
}

function intersects(required: readonly string[], actual: readonly string[]): boolean {
  const actualSet = new Set(actual.map((item) => item.toUpperCase()));
  return required.some((item) => actualSet.has(item.toUpperCase()));
}
