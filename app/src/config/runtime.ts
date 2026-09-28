import { CompositeProbeAdapter } from '../adapters/probe/composite';
import { ExternalApiProbeAdapter } from '../adapters/probe/external-api';
import { SocketProbeAdapter, type SocketConnect } from '../adapters/probe/socket';
import { UnconfiguredProbeAdapter } from '../adapters/probe/unconfigured';
import {
  createDefaultConfig,
  DEFAULT_RUNTIME_SETTINGS,
  MAX_ENDPOINT_URL_LENGTH,
  MAX_PROBE_TIMEOUT_MS,
  MIN_PROBE_TIMEOUT_MS,
  parseSocketProbeUrl,
  PROBE_MODES,
  SETTINGS_LIMITS,
  type ProbeConfig,
  type ProbeMode,
  type AppConfig,
} from '../contracts/config';
import type { ProbeAdapter } from '../ports/probe';

export interface RuntimeEnv {
  readonly CF_KEY?: string;
  readonly CF_ZONEID?: string;
  readonly CF_BASE_DOMAIN?: string;
  readonly AUTH_KEY?: string;
  readonly TG_TOKEN?: string;
  readonly TG_ID?: string;
  readonly SCHEDULED_ENABLED?: string;
  readonly TG_ENABLED?: string;
  readonly PROBE_MODE?: string;
  readonly CHECK_API?: string;
  readonly CHECK_API_BACKUP?: string;
  readonly DOH_API?: string;
  readonly CHECK_TIMEOUT?: string;
  /** socket 模式的双探针地址；留空表示不启用该族。 */
  readonly SOCKET_PROBE_IPV4_URL?: string;
  readonly SOCKET_PROBE_IPV6_URL?: string;
  readonly REMOTE_LOAD_TIMEOUT?: string;
  readonly IP_DATA?: KVNamespace;
}

/** 环境变量只是在 KV 为空时的启动配置，不是第二套账号或配置模型。 */
export function loadEnvConfig(env: RuntimeEnv): AppConfig {
  const defaults = createDefaultConfig();
  const mode = readProbeMode(env.PROBE_MODE);
  const apiKey = env.CF_KEY?.trim() ?? '';
  const zoneId = env.CF_ZONEID?.trim() ?? '';
  const baseDomain = env.CF_BASE_DOMAIN?.trim().replace(/^\.+|\.+$/g, '') ?? '';

  return {
    ...defaults,
    apiKey,
    zoneId,
    zones: apiKey || zoneId || baseDomain
      ? [{ name: baseDomain || '环境变量配置', baseDomain, zoneId, apiKey, label: baseDomain || '环境变量配置' }]
      : defaults.zones,
    checkApi: normalizeCheckApi(env.CHECK_API ?? defaults.checkApi, mode),
    checkApiBackup: normalizeCheckApi(env.CHECK_API_BACKUP ?? defaults.checkApiBackup, mode),
    dohApi: readLengthBounded(env.DOH_API, defaults.dohApi),
    authKey: readLengthBounded(env.AUTH_KEY, defaults.authKey),
    tgToken: readLengthBounded(env.TG_TOKEN, defaults.tgToken),
    tgId: readLengthBounded(env.TG_ID, defaults.tgId, 64),
    scheduledEnabled: readBooleanEnv(env.SCHEDULED_ENABLED, defaults.scheduledEnabled),
    tgEnabled: readBooleanEnv(env.TG_ENABLED, defaults.tgEnabled),
    probeMode: mode,
    socketProbeIpv4Url: readProbeUrlEnv(env.SOCKET_PROBE_IPV4_URL, defaults.socketProbeIpv4Url),
    socketProbeIpv6Url: readProbeUrlEnv(env.SOCKET_PROBE_IPV6_URL, defaults.socketProbeIpv6Url),
    settings: {
      ...DEFAULT_RUNTIME_SETTINGS,
      CHECK_TIMEOUT: parseInteger(env.CHECK_TIMEOUT, defaults.settings.CHECK_TIMEOUT, MIN_PROBE_TIMEOUT_MS, MAX_PROBE_TIMEOUT_MS),
      REMOTE_LOAD_TIMEOUT: parseInteger(
        env.REMOTE_LOAD_TIMEOUT,
        defaults.settings.REMOTE_LOAD_TIMEOUT,
        SETTINGS_LIMITS.REMOTE_LOAD_TIMEOUT.min,
        SETTINGS_LIMITS.REMOTE_LOAD_TIMEOUT.max,
      ),
    },
  };
}

export interface ProbeAdapterDeps {
  readonly fetchImpl?: typeof fetch;
  /**
   * socket 模式必须注入 `cloudflare:sockets` 的 connect：
   * 由 Worker 入口提供，适配器本身不 import 运行时模块，测试可以注入假实现。
   */
  readonly connect?: SocketConnect;
}

/**
 * 运行时探针装配：配置里有哪些链路就建哪些适配器，两条都在时级联判定，
 * 只有一条时就是单条链路。缺少 connect 属于部署错误，按"未配置"处理而不是报 dead。
 */
export function createProbeAdapterFromConfig(config: ProbeConfig, deps: ProbeAdapterDeps = {}): ProbeAdapter {
  const internal = createInternalAdapter(config, deps);
  const external = createExternalAdapter(config, deps);
  if (internal && external) return new CompositeProbeAdapter({ internal, external, primary: config.primary });
  return internal ?? external ?? new UnconfiguredProbeAdapter();
}

function createInternalAdapter(config: ProbeConfig, deps: ProbeAdapterDeps): ProbeAdapter | null {
  if (!deps.connect || (!config.ipv4ProbeUrl && !config.ipv6ProbeUrl)) return null;
  return new SocketProbeAdapter({
    ipv4Url: config.ipv4ProbeUrl,
    ipv6Url: config.ipv6ProbeUrl,
    timeoutMs: config.timeoutMs,
    readLimitBytes: config.readLimitBytes,
    connect: deps.connect,
  });
}

function createExternalAdapter(config: ProbeConfig, deps: ProbeAdapterDeps): ProbeAdapter | null {
  if (config.endpoints.length === 0) return null;
  return new ExternalApiProbeAdapter({
    endpoints: config.endpoints.map(({ name, urlTemplate }) => ({ name, urlTemplate })),
    timeoutMs: config.timeoutMs,
    fallbackToNext: config.fallbackToNext,
    fetchImpl: deps.fetchImpl ?? fetch,
  });
}

function readProbeMode(value: string | undefined): ProbeMode {
  const trimmed = value?.trim();
  return PROBE_MODES.find((mode) => mode === trimmed) ?? 'external-api';
}

/** 环境变量里的探针地址非法时忽略，继续用默认值，避免把坏地址写进运行配置。 */
function readProbeUrlEnv(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim();
  if (!trimmed) return fallback;
  return parseSocketProbeUrl(trimmed) ? trimmed : fallback;
}

function normalizeCheckApi(rawValue: string, mode: ProbeMode): string {
  const value = rawValue.trim();
  if (!value) return '';
  return mode === 'cmliu-check' ? buildCmliuUrlTemplate(value) ?? '' : value;
}

function buildCmliuUrlTemplate(baseUrl: string): string | null {
  try {
    const url = new URL(baseUrl);
    if (!url.pathname.replace(/\/+$/, '').endsWith('/check')) {
      url.pathname = `${url.pathname.replace(/\/+$/, '')}/check`;
    }
    url.searchParams.set('proxyip', '{proxyip}');
    return url.toString().replace('%7Bproxyip%7D', '{proxyip}');
  } catch {
    return null;
  }
}

function parseInteger(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function readLengthBounded(value: string | undefined, fallback: string, max = MAX_ENDPOINT_URL_LENGTH): string {
  if (value === undefined) return fallback;
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : fallback;
}

function readBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off', 'disabled'].includes(normalized)) return false;
  return fallback;
}

