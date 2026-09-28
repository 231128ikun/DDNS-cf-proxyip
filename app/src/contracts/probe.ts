import type { ProbeResult } from '../domain/probe-result';
import {
  MAX_ENDPOINT_URL_LENGTH,
  MAX_SOCKET_READ_LIMIT_BYTES,
  MIN_SOCKET_READ_LIMIT_BYTES,
  PROBE_MODES,
  type ProbeMode,
} from './config';
import { asRecord, parseFail, parseOk, readInteger, readTrimmedString, type ParseResult } from './parse';

export const MAX_PROXYIP_LENGTH = 512;

/** `/api/check` 的 GET query 与 POST body 共用同一份输入校验。 */
export function parseCheckProxyInput(value: unknown): ParseResult<string> {
  const proxyip = readTrimmedString(value, 1, MAX_PROXYIP_LENGTH);
  if (!proxyip) return parseFail(`proxyip must be 1-${MAX_PROXYIP_LENGTH} characters`);
  return parseOk(proxyip);
}

export type ProbeResponse = Omit<ProbeResult, 'target'>;
export type ConfigSource = 'kv' | 'env';

export interface HealthResponse {
  readonly ok: true;
  readonly version: string;
  readonly configSource?: ConfigSource;
}

export interface ApiErrorResponse {
  readonly error: string;
}

/**
 * 接口自检的探针草稿：只带探针相关字段，没出现的字段沿用已保存配置，
 * 因此未保存的改动也能立刻被试一次，而不要求前端先回传整份配置。
 */
export interface ProbeTestDraft {
  readonly probeMode?: ProbeMode;
  readonly checkApi?: string;
  readonly checkApiBackup?: string;
  readonly socketProbeIpv4Url?: string;
  readonly socketProbeIpv6Url?: string;
  readonly socketReadLimitBytes?: number;
}

export interface ProbeTestRequest {
  readonly proxyip: string;
  readonly draft?: ProbeTestDraft;
}

const DRAFT_URL_KEYS = ['checkApi', 'checkApiBackup', 'socketProbeIpv4Url', 'socketProbeIpv6Url'] as const;

/** 自检固定跑满四条链路，这样“没配”和“配了但不通”在界面上能分开看见。 */
export const PROBE_TEST_ITEM_IDS = [
  'internal-ipv4',
  'internal-ipv6',
  'external-primary',
  'external-backup',
] as const;
export type ProbeTestItemId = (typeof PROBE_TEST_ITEM_IDS)[number];

export interface ProbeTestItemResponse {
  readonly id: ProbeTestItemId;
  readonly label: string;
  readonly configured: boolean;
  readonly result?: ProbeResponse;
  readonly error?: string;
}

export interface ProbeTestResponse {
  readonly proxyip: string;
  readonly items: readonly ProbeTestItemResponse[];
}

export function parseProbeTestRequest(value: unknown): ParseResult<ProbeTestRequest> {
  const record = asRecord(value);
  if (!record) return parseFail('自检请求必须是 JSON 对象');

  const proxyip = parseCheckProxyInput(record.proxyip);
  if (!proxyip.ok) return proxyip;

  return parseOk({
    proxyip: proxyip.value,
    ...(record.draft === undefined ? {} : { draft: parseProbeTestDraft(record.draft) }),
  });
}

function parseProbeTestDraft(value: unknown): ProbeTestDraft {
  const record = asRecord(value) ?? {};
  const mode = readTrimmedString(record.probeMode, 1, 32);
  const readLimit = readInteger(record.socketReadLimitBytes, MIN_SOCKET_READ_LIMIT_BYTES, MAX_SOCKET_READ_LIMIT_BYTES);
  return {
    ...(PROBE_MODES.includes(mode as ProbeMode) ? { probeMode: mode as ProbeMode } : {}),
    ...readDraftUrls(record),
    ...(readLimit === null ? {} : { socketReadLimitBytes: readLimit }),
  };
}

function readDraftUrls(record: Record<string, unknown>): Partial<Record<(typeof DRAFT_URL_KEYS)[number], string>> {
  const urls: Partial<Record<(typeof DRAFT_URL_KEYS)[number], string>> = {};
  for (const key of DRAFT_URL_KEYS) {
    if (record[key] === undefined) continue;
    urls[key] = readTrimmedString(record[key], 0, MAX_ENDPOINT_URL_LENGTH) ?? '';
  }
  return urls;
}
