import { asRecord, readClampedInteger } from './parse';

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

/** 小型共用契约：浏览器检测无需导入完整配置解析与权限模型。 */
export function parseRuntimeSettings(value: unknown): RuntimeSettings {
  const raw = asRecord(value) ?? {};
  const result = { ...DEFAULT_RUNTIME_SETTINGS };
  for (const key of Object.keys(SETTINGS_LIMITS) as (keyof RuntimeSettings)[]) {
    const { min, max } = SETTINGS_LIMITS[key];
    result[key] = readClampedInteger(raw[key], DEFAULT_RUNTIME_SETTINGS[key], min, max);
  }
  return result;
}
