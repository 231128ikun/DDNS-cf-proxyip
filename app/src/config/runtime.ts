import { ExternalApiProbeAdapter } from '../adapters/probe/external-api';
import { UnconfiguredProbeAdapter } from '../adapters/probe/unconfigured';
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
    checkApi: readLengthBounded(env.CHECK_API, defaults.checkApi),
    checkApiBackup: readLengthBounded(env.CHECK_API_BACKUP, defaults.checkApiBackup),
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
}

/**
 * 运行时探针装配：没有配置检测接口时返回"未配置"适配器，
 * 这样缺配置只会得到 unknown，不会被误判成节点失效。
 */
export function createProbeAdapterFromConfig(config: ProbeConfig, deps: ProbeAdapterDeps = {}): ProbeAdapter {
  if (config.endpoints.length === 0) return new UnconfiguredProbeAdapter();
  return new ExternalApiProbeAdapter({
    endpoints: config.endpoints.map(({ name, urlTemplate }) => ({ name, urlTemplate })),
    timeoutMs: config.timeoutMs,
    fallbackToNext: config.fallbackToNext,
    fetchImpl: deps.fetchImpl ?? appFetch,
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
