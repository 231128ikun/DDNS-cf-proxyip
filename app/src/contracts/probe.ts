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
export type ConfigSource = 'kv' | 'env';

export interface HealthResponse {
  readonly ok: true;
  readonly version: string;
  readonly configSource?: ConfigSource;
}

export interface ApiErrorResponse {
  readonly error: string;
}
