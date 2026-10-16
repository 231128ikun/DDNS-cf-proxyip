import type { ProbeResult } from '../domain/probe-result';
import { parseFail, parseOk, readTrimmedString, type ParseResult } from './parse';

export const MAX_PROXYIP_LENGTH = 512;

/** `/api/check` 的 GET query 与 POST body 共用同一份输入校验。 */
export function parseCheckProxyInput(value: unknown): ParseResult<string> {
  const proxyip = readTrimmedString(value, 1, MAX_PROXYIP_LENGTH);
  if (!proxyip) return parseFail(`proxyip must be 1-${MAX_PROXYIP_LENGTH} characters`);
  return parseOk(proxyip);
}

export type ProbeResponse = Omit<ProbeResult, 'target'>;

/** 探测入口的解析来源：direct 表示输入本身就是目标，txt/dns 表示先解析出地址再探测。 */
export interface CheckTargetSourceResponse {
  readonly kind: 'direct' | 'txt' | 'dns';
  readonly host?: string;
  readonly addresses?: readonly string[];
}

export interface CheckTargetItemResponse {
  /** 规范化后的地址（含端口）。 */
  readonly address: string;
  readonly result: ProbeResponse;
}

/** `POST /api/check` 的响应：一个输入可能对应多个地址。 */
export interface CheckTargetResponse {
  readonly ok: true;
  readonly input: string;
  readonly source: CheckTargetSourceResponse;
  readonly items: readonly CheckTargetItemResponse[];
  readonly skipped: readonly string[];
}
export type ConfigSource = 'kv' | 'env';

export interface HealthResponse {
  readonly ok: true;
  readonly version: string;
  readonly configSource?: ConfigSource;
}

export interface ApiErrorResponse {
  readonly error: string;
}
