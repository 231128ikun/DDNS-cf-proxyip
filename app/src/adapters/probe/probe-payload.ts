import { exitFamilyFromIp, type ProbeExit, type SingleExitFamily } from '../../domain/probe-result';

/**
 * 探针响应解析的公共规则。
 *
 * 外部检测 API 与双探针 Socket 适配器面对的是同一类出口信息（ip/asn/country），
 * 这里只保留一份解析实现，避免两个适配器各写一套字段兼容。
 */
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
  const family = normalizeSingleExitFamily(readText(record.ipType) ?? readText(record.type) ?? stackHint, ip);
  const asn = normalizeAsn(firstText(record, ['asn', 'as', 'asNumber']));
  const country = firstText(record, ['country', 'countryCode']);
  const organization = firstText(record, ['asOrganization', 'asname', 'org', 'isp']);

  if (!ip && !asn && !country && !organization && family === 'unknown') return null;
  return {
    family,
    ...(ip ? { ip } : {}),
    ...(asn ? { asn } : {}),
    ...(country ? { country: country.toUpperCase() } : {}),
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

function normalizeAsn(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const normalized = value.trim().replace(/^AS/i, '').toUpperCase();
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