import { exitFamilyFromIp, type ProbeExit, type SingleExitFamily } from '../../domain/probe-result';

export type JsonRecord = Record<string, unknown>;

export function readText(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

export function firstText(record: JsonRecord, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = readText(record[key]);
    if (value) return value;
  }
  return undefined;
}

/** 把任意探针响应片段归一成 ProbeExit；完全没有出口信息时返回 null。 */
export function readProbeExit(record: JsonRecord, stackHint: string | undefined): ProbeExit | null {
  const ip = firstText(record, ['ip', 'ipAddress', 'exitIp', 'exit_ip', 'address', 'query']);
  const family = normalizeSingleExitFamily(readText(record.exit_family) ?? readText(record.ipType) ?? readText(record.type) ?? stackHint, ip);
  const asn = normalizeAsn(record.exit_asn) ?? normalizeAsn(record.asn) ?? normalizeAsn(record.as) ?? normalizeAsn(record.asNumber);
  const country = firstText(record, ['exit_country', 'country', 'countryCode']);
  const region = firstText(record, ['exit_region', 'region', 'regionName']);
  const city = firstText(record, ['exit_city', 'city', 'cityName']);
  const organization = firstText(record, ['exit_org', 'asOrganization', 'asname', 'org', 'isp']);

  if (!ip && !asn && !country && !region && !city && !organization && family === 'unknown') return null;
  return {
    family,
    ...(ip ? { ip } : {}),
    ...(asn ? { asn } : {}),
    ...(country ? { country: country.toUpperCase() } : {}),
    ...(region ? { region } : {}),
    ...(city ? { city } : {}),
    ...(organization ? { organization } : {}),
  };
}

export function normalizeSingleExitFamily(value: string | undefined, ip: string | undefined): SingleExitFamily {
  const normalized = value?.trim().toLowerCase().replace(/_/g, '-');
  if (normalized === 'ipv4' || normalized === 'v4' || normalized === 'ipv4-only' || normalized === 'only-ipv4') return 'ipv4';
  if (normalized === 'ipv6' || normalized === 'v6' || normalized === 'ipv6-only' || normalized === 'only-ipv6') return 'ipv6';
  const inferred = exitFamilyFromIp(ip);
  return inferred === 'ipv4' || inferred === 'ipv6' ? inferred : 'unknown';
}

function normalizeAsn(value: unknown): string | undefined {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? String(value) : undefined;
  const text = readText(value);
  if (!text) return undefined;
  const normalized = text.replace(/^AS/i, '').toUpperCase();
  return normalized || undefined;
}

export function uniqueExits(exits: readonly ProbeExit[]): readonly ProbeExit[] {
  const seen = new Set<string>();
  return exits.filter((exit) => {
    const key = `${exit.family}:${exit.ip ?? ''}:${exit.asn ?? ''}:${exit.country ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
