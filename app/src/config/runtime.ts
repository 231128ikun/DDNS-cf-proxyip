import { ExternalApiProbeAdapter } from '../adapters/probe/external-api';
import { NativeProbeAdapter, type ProbeConnect } from '../adapters/probe/native';
import {
  createDefaultConfig,
  DEFAULT_RUNTIME_SETTINGS,
  MAX_ENDPOINT_URL_LENGTH,
  MAX_PROBE_TIMEOUT_MS,
  MIN_PROBE_TIMEOUT_MS,
  SETTINGS_LIMITS,
  type AppConfig,
  type ProbeConfig,
} from '../contracts/config';
import type { ProbeAdapter } from '../ports/probe';
import { appFetch } from '../util/fetch';
import { readClampedInteger as parseInteger } from '../contracts/parse';

export interface RuntimeEnv {
  readonly CF_KEY?: string;
  readonly CF_ZONEID?: string;
  readonly CF_BASE_DOMAIN?: string;
  readonly TG_TOKEN?: string;
  readonly TG_ID?: string;
  readonly SCHEDULED_ENABLED?: string;
  readonly TG_ENABLED?: string;
  readonly CHECK_API?: string;
  readonly CHECK_API_BACKUP?: string;
  readonly PROBE_IPV4_URL?: string;
  readonly PROBE_IPV6_URL?: string;
  readonly AUTH_KEY?: string;
  /** 公共 DNS 查询接口；`txt@域名` 与裸域名探测都依赖它。 */
  readonly DOH_API?: string;
  readonly CONCURRENT_CHECKS?: string;
  readonly CHECK_TIMEOUT?: string;
  readonly REMOTE_LOAD_TIMEOUT?: string;
  readonly DOH_TIMEOUT?: string;
  readonly IP_DATA?: KVNamespace;
}

/** 环境变量只是在 KV 为空时的启动配置，不是第二套账号或配置模型。 */
export function loadEnvConfig(env: RuntimeEnv): AppConfig {
  const defaults = createDefaultConfig();
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
    authKey: readLengthBounded(env.AUTH_KEY, defaults.authKey),
    probeIpv4Url: readLengthBounded(env.PROBE_IPV4_URL, defaults.probeIpv4Url),
    probeIpv6Url: readLengthBounded(env.PROBE_IPV6_URL, defaults.probeIpv6Url),
    checkApiBackup: readLengthBounded(env.CHECK_API_BACKUP ?? env.CHECK_API, defaults.checkApiBackup),
    dohApi: readLengthBounded(env.DOH_API, defaults.dohApi),
    tgToken: readLengthBounded(env.TG_TOKEN, defaults.tgToken),
    tgId: readLengthBounded(env.TG_ID, defaults.tgId, 64),
    scheduledEnabled: readBooleanEnv(env.SCHEDULED_ENABLED, defaults.scheduledEnabled),
    tgEnabled: readBooleanEnv(env.TG_ENABLED, defaults.tgEnabled),
    settings: {
      ...DEFAULT_RUNTIME_SETTINGS,
      CONCURRENT_CHECKS: parseInteger(
        env.CONCURRENT_CHECKS, defaults.settings.CONCURRENT_CHECKS,
        SETTINGS_LIMITS.CONCURRENT_CHECKS.min, SETTINGS_LIMITS.CONCURRENT_CHECKS.max,
      ),
      CHECK_TIMEOUT: parseInteger(env.CHECK_TIMEOUT, defaults.settings.CHECK_TIMEOUT, MIN_PROBE_TIMEOUT_MS, MAX_PROBE_TIMEOUT_MS),
      REMOTE_LOAD_TIMEOUT: parseInteger(
        env.REMOTE_LOAD_TIMEOUT,
        defaults.settings.REMOTE_LOAD_TIMEOUT,
        SETTINGS_LIMITS.REMOTE_LOAD_TIMEOUT.min,
        SETTINGS_LIMITS.REMOTE_LOAD_TIMEOUT.max,
      ),
      DOH_TIMEOUT: parseInteger(
        env.DOH_TIMEOUT, defaults.settings.DOH_TIMEOUT,
        SETTINGS_LIMITS.DOH_TIMEOUT.min, SETTINGS_LIMITS.DOH_TIMEOUT.max,
      ),
    },
  };
}

export interface ProbeAdapterDeps {
  readonly fetchImpl?: typeof fetch;
  readonly connect?: ProbeConnect;
  readonly budget?: ReturnType<typeof createSubrequestBudget>;
}

/** 按一次调用累计，探测先停，给 DNS 和通知留出空间。 */
export function createSubrequestBudget() {
  let used = 0;
  const take = (ceiling: number): boolean => {
    if (used >= ceiling) return false;
    used++;
    return true;
  };
  const boundedFetch = (ceiling: number): typeof fetch => async (input, init) => {
    if (!take(ceiling)) throw new Error('本轮外部请求预算已用尽');
    return appFetch(input, { ...init, redirect: 'manual' });
  };
  return { takeProbeAttempt: () => take(36), rootsFetch: boundedFetch(36), dnsFetch: boundedFetch(44), notifyFetch: boundedFetch(48) };
}

/** 原生检测优先，失败时备用 API 复检；未配置备用时原生重试一次。 */
export function createProbeAdapterFromConfig(config: ProbeConfig, deps: ProbeAdapterDeps = {}): ProbeAdapter {
  const budget = deps.budget ?? createSubrequestBudget();
  let sockets: Promise<typeof import('cloudflare:sockets')> | undefined;
  const connect: ProbeConnect = deps.connect ?? (async (address, options) => {
    const api = await (sockets ??= import('cloudflare:sockets')).catch(() => { throw new TypeError('socket API unavailable'); });
    return api.connect(address, options);
  });
  const backup = config.endpoints.length ? new ExternalApiProbeAdapter({
    endpoints: config.endpoints,
    timeoutMs: config.timeoutMs,
    fallbackToNext: false,
    // 不自动跟随重定向，确保一次复检只用一个外部请求。
    fetchImpl: deps.fetchImpl ?? ((input, init) => appFetch(input, { ...init, redirect: 'manual' })),
    onDiagnostic: diagnostic => console.warn('[probe-anomaly]', diagnostic),
  }) : undefined;
  return new NativeProbeAdapter({ urls: config.urls, timeoutMs: config.timeoutMs,
    connect,
    takeAttempt: budget.takeProbeAttempt, rootsFetch: budget.rootsFetch,
    ...(backup ? { backup } : {}),
  });
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
