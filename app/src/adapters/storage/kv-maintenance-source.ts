import { DOMAIN_POOL_MAPPING_KEY, POOL_NAMES_KEY } from '../../contracts/pool';
import { normalizeManagedTarget } from '../../domain/managed-target';
import type { DnsZone } from '../../ports/dns-repository';
import type { MaintenanceSource, MaintenanceSourceData, MaintenanceTargetConfig } from '../../ports/maintenance-source';
import { CONFIG_KEY } from './kv-config-repository';
import { readKvJson, readKvStringRecord } from './kv-json';

/** 维护目标直接来自统一配置 `app_config`，不再维护第二份域名配置。 */
export class KvMaintenanceSource implements MaintenanceSource {
  constructor(private readonly kv: KVNamespace) {}

  async load(): Promise<MaintenanceSourceData> {
    const [configResult, poolMapping, poolNames] = await Promise.all([
      readKvJson(this.kv, CONFIG_KEY, 60),
      readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY),
      readKvStringRecord(this.kv, POOL_NAMES_KEY),
    ]);

    if (configResult.status === 'invalid') throw new Error(`配置无法读取：${configResult.message}`);
    const record = asRecord(configResult.status === 'loaded' ? configResult.value : null);
    return {
      zones: toArray(record?.zones).map(normalizeZone).filter(isPresent),
      targets: toArray(record?.targets).map(normalizeTarget).filter(isPresent),
      poolMapping,
      poolNames,
    };
  }
}

/** 与旧版 `normalizeZoneConfig` 保持同样的空条目丢弃规则。 */
function normalizeZone(value: unknown): DnsZone | null {
  const record = asRecord(value);
  if (!record) return null;

  const baseDomain = text(record.baseDomain) || text(record.domain);
  const zoneId = text(record.zoneId);
  const apiToken = text(record.apiKey);
  if (!baseDomain && !zoneId && !apiToken) return null;
  return { zoneId, apiToken };
}

function normalizeTarget(value: unknown): MaintenanceTargetConfig | null {
  const record = asRecord(value);
  if (!record) return null;

  const domain = text(record.domain) || buildDomain(text(record.prefix), text(record.baseDomain));
  const target = normalizeManagedTarget({
    domain,
    mode: text(record.mode),
    port: scalar(record.port),
    minActive: scalar(record.minActive),
    exitFilter: text(record.exitFilter),
    countries: preferList(record.countries, record.country),
    asns: preferList(record.asns, record.asn),
  });
  if (!target) return null;
  return { target, zoneIndex: readZoneIndex(record.zoneIndex), enabled: record.enabled !== false };
}

function buildDomain(prefix: string, baseDomain: string): string {
  const cleanPrefix = prefix.replace(/^\.+|\.+$/g, '');
  const cleanBase = baseDomain.replace(/^\.+|\.+$/g, '');
  if (!cleanBase) return '';
  return cleanPrefix ? `${cleanPrefix}.${cleanBase}` : cleanBase;
}

function readZoneIndex(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function preferList(primary: unknown, fallback: unknown): readonly string[] | string | undefined {
  if (Array.isArray(primary) && primary.length > 0) return primary.map((item) => String(item));
  const primaryText = text(primary);
  if (primaryText) return primaryText;
  return text(fallback) || undefined;
}

function toArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function scalar(value: unknown): string | number | undefined {
  return typeof value === 'string' || typeof value === 'number' ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function isPresent<T>(value: T | null): value is T {
  return value !== null;
}
