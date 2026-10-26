import type { ExitFilter, TargetMode } from '../domain/managed-target';
import { normalizeAsn, normalizeCountry } from '../domain/pool-entry';
import { asRecord, parseFail, parseOk, readClampedInteger as integerValue, type ParseResult } from './parse';
import { DEFAULT_RUNTIME_SETTINGS, parseRuntimeSettings, type RuntimeSettings } from './runtime-settings';
export { DEFAULT_RUNTIME_SETTINGS, SETTINGS_LIMITS, parseRuntimeSettings, type RuntimeSettings } from './runtime-settings';

export const MIN_PROBE_TIMEOUT_MS = 500;
export const MAX_PROBE_TIMEOUT_MS = 30_000;
export const MAX_ENDPOINT_URL_LENGTH = 2_048;
export const MAX_SECRET_LENGTH = 512;
export const MAX_ZONE_ID_LENGTH = 64;
export const MAX_ZONES = 20;
export const MAX_TARGETS = 100;
export const MAX_TARGET_PORT = 65_535;
export const MAX_MIN_ACTIVE = 100;

/** 运行时探针配置；不是 KV 数据模型，只由 AppConfig 派生。 */
export interface ExternalApiEndpoint {
  readonly name: string;
  readonly urlTemplate: string;
}

export interface ProbeConfig {
  readonly endpoints: readonly ExternalApiEndpoint[];
  readonly fallbackToNext: boolean;
  readonly timeoutMs: number;
}

export interface ZoneConfig {
  readonly name: string;
  readonly baseDomain: string;
  readonly zoneId: string;
  readonly apiKey: string;
  readonly label: string;
}

export interface TargetConfig {
  readonly mode: TargetMode;
  readonly domain: string;
  readonly baseDomain: string;
  readonly prefix: string;
  readonly zoneIndex: number | null;
  readonly port: number | 'any';
  readonly minActive: number;
  readonly exitFilter: ExitFilter;
  readonly country: string;
  readonly asn: string;
  readonly countries: readonly string[];
  readonly asns: readonly string[];
  readonly enabled: boolean;
}

/** 与既有 app_config 直接对应；扩展字段仍存放在同一个对象。 */
export interface AppConfig {
  readonly apiKey: string;
  readonly zoneId: string;
  readonly zones: readonly ZoneConfig[];
  readonly targets: readonly TargetConfig[];
  readonly checkApi: string;
  readonly checkApiBackup: string;
  readonly dohApi: string;
  readonly tgToken: string;
  readonly tgId: string;
  readonly scheduledEnabled: boolean;
  readonly tgEnabled: boolean;
  readonly settings: RuntimeSettings;
  readonly projectUrl: string;
}

export interface PublicZoneConfig {
  readonly name: string;
  readonly baseDomain: string;
  readonly zoneId: string;
  readonly label: string;
  readonly hasApiKey: boolean;
}

export interface PublicAppConfig {
  readonly zones: readonly PublicZoneConfig[];
  readonly targets: readonly TargetConfig[];
  readonly zoneId: string;
  readonly checkApi: string;
  readonly checkApiBackup: string;
  readonly dohApi: string;
  readonly tgId: string;
  readonly scheduledEnabled: boolean;
  readonly tgEnabled: boolean;
  readonly settings: RuntimeSettings;
  readonly projectUrl: string;
  readonly secrets: {
    readonly apiKey: boolean;
    readonly tgToken: boolean;
  };
}

export interface ConfigResponse {
  readonly source: 'kv' | 'env';
  readonly notice?: string;
  readonly config: PublicAppConfig;
}

export type ConfigUpdateRequest =
  Omit<Partial<AppConfig>, 'settings'> & { readonly settings?: Partial<RuntimeSettings> };

export function createDefaultConfig(): AppConfig {
  return {
    apiKey: '',
    zoneId: '',
    zones: [],
    targets: [],
    checkApi: '',
    checkApiBackup: 'https://checkapi.dvb.kdns.fr/?candidate=',
    dohApi: 'https://cloudflare-dns.com/dns-query',
    tgToken: '',
    tgId: '',
    scheduledEnabled: true,
    tgEnabled: true,
    settings: { ...DEFAULT_RUNTIME_SETTINGS },
    projectUrl: '',
  };
}

export function toPublicConfig(config: AppConfig): PublicAppConfig {
  return {
    zones: config.zones.map(({ name, baseDomain, zoneId, label, apiKey }) => ({
      name,
      baseDomain,
      zoneId,
      label,
      hasApiKey: apiKey.length > 0,
    })),
    targets: config.targets,
    zoneId: config.zoneId,
    checkApi: config.checkApi,
    checkApiBackup: config.checkApiBackup,
    dohApi: config.dohApi,
    tgId: config.tgId,
    scheduledEnabled: config.scheduledEnabled,
    tgEnabled: config.tgEnabled,
    settings: config.settings,
    projectUrl: config.projectUrl,
    secrets: {
      apiKey: config.apiKey.length > 0,
      tgToken: config.tgToken.length > 0,
    },
  };
}

export function toProbeConfig(config: AppConfig): ProbeConfig {
  const endpoints: ExternalApiEndpoint[] = [];
  if (config.checkApi.trim()) endpoints.push({ name: 'primary', urlTemplate: config.checkApi.trim() });
  if (config.checkApiBackup.trim()) endpoints.push({ name: 'backup', urlTemplate: config.checkApiBackup.trim() });
  return {
    endpoints,
    fallbackToNext: true,
    timeoutMs: config.settings.CHECK_TIMEOUT,
  };
}

/** 读取 KV 或请求体时沿用“能修就修、不能修就忽略该条”的宽松规则。 */
export function parseAppConfig(value: unknown, previous?: AppConfig): ParseResult<AppConfig> {
  const record = asRecord(value);
  if (!record) return parseFail('配置必须是 JSON 对象');
  const base = previous ?? createDefaultConfig();
  // 旧 KV 与部分更新都只覆盖提供的字段，未提交的运行参数沿用已解析配置。
  const settings = parseRuntimeSettings({ ...base.settings, ...(asRecord(record.settings) ?? {}) });
  const parsedZones = Array.isArray(record.zones) ? parseZones(record.zones, base.zones) : parseOk(base.zones);
  if (!parsedZones.ok) return parsedZones;
  const zones = parsedZones.value;
  const targets = Array.isArray(record.targets) ? parseTargets(record.targets, settings) : base.targets;
  const duplicate = findDuplicate(zones, targets);
  if (duplicate) return parseFail(duplicate);
  const apiKey = zones[0]?.apiKey || text(record.apiKey, base.apiKey, MAX_SECRET_LENGTH);
  const zoneId = zones[0]?.zoneId || text(record.zoneId, base.zoneId, MAX_ZONE_ID_LENGTH);

  return parseOk({
    apiKey,
    zoneId,
    zones,
    targets,
    checkApi: text(record.checkApi, base.checkApi, MAX_ENDPOINT_URL_LENGTH),
    checkApiBackup: text(record.checkApiBackup, base.checkApiBackup, MAX_ENDPOINT_URL_LENGTH),
    dohApi: text(record.dohApi, base.dohApi, MAX_ENDPOINT_URL_LENGTH),
    tgToken: text(record.tgToken, base.tgToken, MAX_SECRET_LENGTH),
    tgId: text(record.tgId, base.tgId, 64),
    scheduledEnabled: booleanValue(record.scheduledEnabled, base.scheduledEnabled),
    tgEnabled: booleanValue(record.tgEnabled, base.tgEnabled),
    settings,
    projectUrl: text(record.projectUrl, base.projectUrl, MAX_ENDPOINT_URL_LENGTH),
  });
}

function parseZones(values: readonly unknown[], previous: readonly ZoneConfig[]): ParseResult<readonly ZoneConfig[]> {
  const zones: ZoneConfig[] = [];
  for (const value of values.slice(0, MAX_ZONES)) {
    const parsed = normalizeZone(value, previous);
    if (!parsed.ok) return parsed;
    if (parsed.value) zones.push(parsed.value);
  }
  return parseOk(zones);
}

function parseTargets(values: readonly unknown[], settings: RuntimeSettings): readonly TargetConfig[] {
  return values.slice(0, MAX_TARGETS).map((item) => normalizeTarget(item, settings)).filter((target): target is TargetConfig => target !== null);
}

function normalizeZone(value: unknown, previous: readonly ZoneConfig[]): ParseResult<ZoneConfig | null> {
  const record = asRecord(value);
  if (!record) return parseOk(null);
  const baseDomain = text(record.baseDomain, text(record.domain, '', 253), 253).replace(/^\.+|\.+$/g, '');
  const zoneId = text(record.zoneId, '', MAX_ZONE_ID_LENGTH);
  const label = text(record.label, text(record.name, baseDomain || zoneId || '未命名', 32), 32);
  // 面板不回传已保存的 Token；删除或排序后按区域身份保留，不能按数组位置串用凭据。
  let matches = previous.filter((zone) => {
    if (zoneId && zone.zoneId) return zone.zoneId === zoneId;
    if (baseDomain && zone.baseDomain) return zone.baseDomain.toLowerCase() === baseDomain.toLowerCase();
    return !zoneId && !baseDomain && !zone.zoneId && !zone.baseDomain && zone.label === label;
  });
  const replacement = text(record.apiKey, '', MAX_SECRET_LENGTH);
  if (matches.length > 1 && baseDomain) {
    const domainMatches = matches.filter(zone => zone.baseDomain.toLowerCase() === baseDomain.toLowerCase());
    if (domainMatches.length === 1) matches = domainMatches;
  }
  if (!replacement && matches.length > 1) return parseFail('已保存的权限 Token 无法唯一匹配，请填写 CF Key 后保存');
  const apiKey = replacement || (matches.length === 1 ? matches[0]!.apiKey : '');
  if (!baseDomain && !zoneId && !apiKey) return parseOk(null);
  return parseOk({ name: label, baseDomain, zoneId, apiKey, label });
}

function normalizeTarget(value: unknown, settings: RuntimeSettings): TargetConfig | null {
  const record = asRecord(value);
  if (!record) return null;
  const mode: TargetMode = String(record.mode ?? 'A').trim().toUpperCase() === 'TXT' ? 'TXT' : 'A';
  const prefix = text(record.prefix, '', 63).replace(/^\.+|\.+$/g, '');
  const baseDomain = text(record.baseDomain, '', 253).replace(/^\.+|\.+$/g, '');
  const domain = text(record.domain, buildDomain(prefix, baseDomain), 253).replace(/\.$/, '').toLowerCase();
  if (!domain) return null;
  const rawPort = record.port === undefined ? '443' : String(record.port).trim();
  const portNumber = Number.parseInt(rawPort, 10);
  const port = mode === 'TXT' ? 'any' : Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= MAX_TARGET_PORT ? portNumber : 443;
  const countries = normalizeList(record.countries, record.country, normalizeCountry);
  const asns = normalizeList(record.asns, record.asn, normalizeAsn);
  return {
    mode,
    domain,
    baseDomain,
    prefix,
    zoneIndex: readZoneIndex(record.zoneIndex),
    port,
    minActive: integerValue(record.minActive, settings.DEFAULT_MIN_ACTIVE, 0, MAX_MIN_ACTIVE),
    exitFilter: normalizeExitFilter(record.exitFilter),
    country: countries.join(','),
    asn: asns.join(','),
    countries,
    asns,
    enabled: record.enabled !== false,
  };
}

function normalizeList(
  primary: unknown,
  fallback: unknown,
  normalizer: (item: string | null | undefined) => string | undefined,
): readonly string[] {
  const source = Array.isArray(primary) && primary.length > 0 ? primary : fallback;
  const values = Array.isArray(source) ? source : String(source ?? '').split(/[,;，；\s]+/);
  return [...new Set(values.map((item) => normalizer(String(item).trim())).filter((item): item is string => Boolean(item)))];
}

function normalizeExitFilter(value: unknown): ExitFilter {
  const textValue = String(value ?? '').trim().toLowerCase().replace(/_/g, '-');
  if (!textValue || ['any', 'all', 'v4/v6', 'v6/v4'].includes(textValue)) return 'any';
  if (['v4', 'ipv4', 'ipv4-only', 'only-ipv4'].includes(textValue)) return 'v4';
  if (['v6', 'ipv6', 'ipv6-only', 'only-ipv6'].includes(textValue)) return 'v6';
  if (['dual', 'dual-stack', 'both'].includes(textValue)) return 'dual';
  return 'any';
}

function findDuplicate(zones: readonly ZoneConfig[], targets: readonly TargetConfig[]): string {
  const zoneKeys = new Set<string>();
  for (const zone of zones) {
    const key = zone.baseDomain.trim().toLowerCase();
    if (key && zoneKeys.has(key)) return `权限配置存在重复目标维护域名：${key}`;
    zoneKeys.add(key);
  }
  const targetKeys = new Set<string>();
  for (const target of targets) {
    const key = `${target.domain}|${target.mode}`;
    if (targetKeys.has(key)) return `管理域名存在重复项：${target.domain} / ${target.mode === 'TXT' ? 'TXT' : 'A/AAAA'}`;
    targetKeys.add(key);
  }
  return '';
}

function readZoneIndex(value: unknown): number | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function buildDomain(prefix: string, baseDomain: string): string {
  return prefix ? `${prefix}.${baseDomain}` : baseDomain;
}

function text(value: unknown, fallback: string, max: number): string {
  if (value === undefined) return fallback;
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off', 'disabled'].includes(normalized)) return false;
  return fallback;
}
