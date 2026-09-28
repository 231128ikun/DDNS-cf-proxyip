import type { ExitFilter, TargetMode } from '../domain/managed-target';
import { normalizeAsn, normalizeCountry } from '../domain/pool-entry';
import { asRecord, parseFail, parseOk, type ParseResult } from './parse';

export const PROBE_MODES = ['external-api', 'cmliu-check', 'socket'] as const;
export type ProbeMode = (typeof PROBE_MODES)[number];

export const DEFAULT_PROBE_TIMEOUT_MS = 15_000;
export const MIN_PROBE_TIMEOUT_MS = 500;
export const MAX_PROBE_TIMEOUT_MS = 30_000;
export const MAX_ENDPOINT_URL_LENGTH = 2_048;
export const DEFAULT_SOCKET_PROBE_IPV4_URL = 'https://ipv4.090227.xyz/';
export const DEFAULT_SOCKET_PROBE_IPV6_URL = 'https://ipv6.090227.xyz/';
export const DEFAULT_SOCKET_READ_LIMIT_BYTES = 65_536;
export const MIN_SOCKET_READ_LIMIT_BYTES = 1_024;
export const MAX_SOCKET_READ_LIMIT_BYTES = 262_144;
export const MAX_SECRET_LENGTH = 512;
export const MAX_ZONE_ID_LENGTH = 64;
export const MAX_ZONES = 20;
export const MAX_TARGETS = 100;
export const MAX_PREFIX_LENGTH = 63;
export const MIN_TARGET_PORT = 1;
export const MAX_TARGET_PORT = 65_535;
export const MAX_MIN_ACTIVE = 100;
export const MAX_PROBE_ENDPOINTS = 2;
export const TARGET_MODES = ['A', 'TXT'] as const;

/** socket 适配器只需要解析后的 endpoint、Host 和 path。 */
export interface SocketProbeUrl {
  readonly endpoint: string;
  readonly hostHeader: string;
  readonly path: string;
}

export function parseSocketProbeUrl(value: string): SocketProbeUrl | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'https:' || !url.hostname) return null;
    const port = url.port ? Number(url.port) : 443;
    return {
      endpoint: url.hostname,
      hostHeader: port === 443 ? url.hostname : `${url.hostname}:${port}`,
      path: `${url.pathname || '/'}${url.search}`,
    };
  } catch {
    return null;
  }
}

/** 运行时探针配置；不是 KV 数据模型，只由 AppConfig 派生。 */
export interface ExternalApiEndpoint {
  readonly name: string;
  readonly urlTemplate: string;
}

/** 主检测链路：内部 socket 双探针先行，外部接口作为复检；两者都会参与同一次判定。 */
export type ProbePrimary = 'internal' | 'external';

export interface ProbeConfig {
  readonly primary: ProbePrimary;
  readonly endpoints: readonly ExternalApiEndpoint[];
  readonly fallbackToNext: boolean;
  readonly timeoutMs: number;
  readonly ipv4ProbeUrl: string;
  readonly ipv6ProbeUrl: string;
  readonly readLimitBytes: number;
}

export interface RuntimeSettings {
  readonly CONCURRENT_CHECKS: number;
  readonly BACKEND_CONCURRENT_CHECKS: number;
  readonly CHECK_TIMEOUT: number;
  readonly REMOTE_LOAD_TIMEOUT: number;
  readonly DOH_TIMEOUT: number;
  readonly DEFAULT_MIN_ACTIVE: number;
  readonly MAX_TRASH_SIZE: number;
}

export const SETTINGS_LIMITS = {
  CONCURRENT_CHECKS: { min: 1, max: 128 },
  BACKEND_CONCURRENT_CHECKS: { min: 1, max: 6 },
  CHECK_TIMEOUT: { min: 500, max: 30_000 },
  REMOTE_LOAD_TIMEOUT: { min: 1_000, max: 60_000 },
  DOH_TIMEOUT: { min: 1_000, max: 30_000 },
  DEFAULT_MIN_ACTIVE: { min: 0, max: 100 },
  MAX_TRASH_SIZE: { min: 0, max: 100_000 },
} as const;

export const DEFAULT_RUNTIME_SETTINGS: RuntimeSettings = {
  CONCURRENT_CHECKS: 32,
  BACKEND_CONCURRENT_CHECKS: 4,
  CHECK_TIMEOUT: 15_000,
  REMOTE_LOAD_TIMEOUT: 8_000,
  DOH_TIMEOUT: 5_000,
  DEFAULT_MIN_ACTIVE: 3,
  MAX_TRASH_SIZE: 1_000,
};

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
  readonly authKey: string;
  readonly tgToken: string;
  readonly tgId: string;
  readonly scheduledEnabled: boolean;
  readonly tgEnabled: boolean;
  readonly settings: RuntimeSettings;
  readonly projectUrl: string;
  readonly probeMode: ProbeMode;
  readonly socketProbeIpv4Url: string;
  readonly socketProbeIpv6Url: string;
  readonly socketReadLimitBytes: number;
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
  readonly probeMode: ProbeMode;
  readonly socketProbeIpv4Url: string;
  readonly socketProbeIpv6Url: string;
  readonly socketReadLimitBytes: number;
  readonly secrets: {
    readonly apiKey: boolean;
    readonly authKey: boolean;
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


export const CONFIG_KEYS = [
  'apiKey', 'zoneId', 'zones', 'targets', 'checkApi', 'checkApiBackup', 'dohApi', 'authKey',
  'tgToken', 'tgId', 'scheduledEnabled', 'tgEnabled', 'settings', 'projectUrl', 'probeMode',
  'socketProbeIpv4Url', 'socketProbeIpv6Url', 'socketReadLimitBytes',
] as const;

export function createDefaultConfig(): AppConfig {
  return {
    apiKey: '',
    zoneId: '',
    zones: [],
    targets: [],
    checkApi: '',
    checkApiBackup: 'https://checkapi.dvb.kdns.fr/?candidate=',
    dohApi: 'https://cloudflare-dns.com/dns-query',
    authKey: '',
    tgToken: '',
    tgId: '',
    scheduledEnabled: true,
    tgEnabled: true,
    settings: { ...DEFAULT_RUNTIME_SETTINGS },
    projectUrl: '',
    probeMode: 'external-api',
    socketProbeIpv4Url: DEFAULT_SOCKET_PROBE_IPV4_URL,
    socketProbeIpv6Url: DEFAULT_SOCKET_PROBE_IPV6_URL,
    socketReadLimitBytes: DEFAULT_SOCKET_READ_LIMIT_BYTES,
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
    probeMode: config.probeMode,
    socketProbeIpv4Url: config.socketProbeIpv4Url,
    socketProbeIpv6Url: config.socketProbeIpv6Url,
    socketReadLimitBytes: config.socketReadLimitBytes,
    secrets: {
      apiKey: config.apiKey.length > 0,
      authKey: config.authKey.length > 0,
      tgToken: config.tgToken.length > 0,
    },
  };
}

export function toProbeConfig(config: AppConfig): ProbeConfig {
  const endpoints: ExternalApiEndpoint[] = [];
  if (config.checkApi.trim()) endpoints.push({ name: 'primary', urlTemplate: config.checkApi.trim() });
  if (config.checkApiBackup.trim()) endpoints.push({ name: 'backup', urlTemplate: config.checkApiBackup.trim() });
  return {
    primary: config.probeMode === 'socket' ? 'internal' : 'external',
    endpoints,
    fallbackToNext: true,
    timeoutMs: config.settings.CHECK_TIMEOUT,
    ipv4ProbeUrl: config.socketProbeIpv4Url,
    ipv6ProbeUrl: config.socketProbeIpv6Url,
    readLimitBytes: config.socketReadLimitBytes,
  };
}

/** 读取 KV 或请求体时沿用“能修就修、不能修就忽略该条”的宽松规则。 */
export function parseAppConfig(value: unknown, previous?: AppConfig): ParseResult<AppConfig> {
  const record = asRecord(value);
  if (!record) return parseFail('配置必须是 JSON 对象');
  const base = previous ?? createDefaultConfig();
  const settings = parseRuntimeSettings(record.settings ?? base.settings);
  const zones = Array.isArray(record.zones) ? parseZones(record.zones, base.zones) : base.zones;
  const targets = Array.isArray(record.targets) ? parseTargets(record.targets, settings) : base.targets;
  const duplicate = findDuplicate(zones, targets);
  if (duplicate) return parseFail(duplicate);
  const apiKey = zones[0]?.apiKey || text(record.apiKey, base.apiKey, MAX_SECRET_LENGTH);
  const zoneId = zones[0]?.zoneId || text(record.zoneId, base.zoneId, MAX_ZONE_ID_LENGTH);

  const probeMode = PROBE_MODES.includes(record.probeMode as ProbeMode)
    ? record.probeMode as ProbeMode
    : base.probeMode;

  return parseOk({
    apiKey,
    zoneId,
    zones,
    targets,
    checkApi: text(record.checkApi, base.checkApi, MAX_ENDPOINT_URL_LENGTH),
    checkApiBackup: text(record.checkApiBackup, base.checkApiBackup, MAX_ENDPOINT_URL_LENGTH),
    dohApi: text(record.dohApi, base.dohApi, MAX_ENDPOINT_URL_LENGTH),
    authKey: text(record.authKey, base.authKey, MAX_SECRET_LENGTH),
    tgToken: text(record.tgToken, base.tgToken, MAX_SECRET_LENGTH),
    tgId: text(record.tgId, base.tgId, 64),
    scheduledEnabled: booleanValue(record.scheduledEnabled, base.scheduledEnabled),
    tgEnabled: booleanValue(record.tgEnabled, base.tgEnabled),
    settings,
    projectUrl: text(record.projectUrl, base.projectUrl, MAX_ENDPOINT_URL_LENGTH),
    probeMode,
    socketProbeIpv4Url: probeUrl(record.socketProbeIpv4Url, base.socketProbeIpv4Url),
    socketProbeIpv6Url: probeUrl(record.socketProbeIpv6Url, base.socketProbeIpv6Url),
    socketReadLimitBytes: integerValue(
      record.socketReadLimitBytes,
      base.socketReadLimitBytes,
      MIN_SOCKET_READ_LIMIT_BYTES,
      MAX_SOCKET_READ_LIMIT_BYTES,
    ),
  });
}

export function parseRuntimeSettings(value: unknown): RuntimeSettings {
  const raw = asRecord(value) ?? {};
  const result = { ...DEFAULT_RUNTIME_SETTINGS } as Record<keyof RuntimeSettings, number>;
  for (const key of Object.keys(SETTINGS_LIMITS) as (keyof RuntimeSettings)[]) {
    const limits = SETTINGS_LIMITS[key];
    result[key] = integerValue(raw[key], DEFAULT_RUNTIME_SETTINGS[key], limits.min, limits.max);
  }
  return result;
}

function parseZones(values: readonly unknown[], previous: readonly ZoneConfig[]): readonly ZoneConfig[] {
  return values
    .slice(0, MAX_ZONES)
    .map((value, index) => normalizeZone(value, previous[index]))
    .filter((zone): zone is ZoneConfig => zone !== null);
}

function parseTargets(values: readonly unknown[], settings: RuntimeSettings): readonly TargetConfig[] {
  return values.slice(0, MAX_TARGETS).map((item) => normalizeTarget(item, settings)).filter((target): target is TargetConfig => target !== null);
}

function normalizeZone(value: unknown, previous?: ZoneConfig): ZoneConfig | null {
  const record = asRecord(value);
  if (!record) return null;
  const baseDomain = text(record.baseDomain, text(record.domain, '', 253), 253).replace(/^\.+|\.+$/g, '');
  const zoneId = text(record.zoneId, '', MAX_ZONE_ID_LENGTH);
  const apiKey = text(record.apiKey, '', MAX_SECRET_LENGTH) || previous?.apiKey || '';
  const label = text(record.label, text(record.name, baseDomain || zoneId || '未命名', 32), 32);
  if (!baseDomain && !zoneId && !apiKey) return null;
  return { name: label, baseDomain, zoneId, apiKey, label };
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

function integerValue(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isInteger(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off', 'disabled'].includes(normalized)) return false;
  return fallback;
}

function probeUrl(value: unknown, fallback: string): string {
  if (value === undefined) return fallback;
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  if (!trimmed) return '';
  return parseSocketProbeUrl(trimmed) ? trimmed : fallback;
}
