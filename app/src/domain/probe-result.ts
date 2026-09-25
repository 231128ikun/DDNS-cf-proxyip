import type { ProxyTarget } from './proxy-target';

export type ProbeStatus = 'alive' | 'dead' | 'unknown';
export type ExitFamily = 'ipv4' | 'ipv6' | 'dual' | 'unknown';
export type SingleExitFamily = 'ipv4' | 'ipv6' | 'unknown';

export interface ProbeExit {
  readonly family: SingleExitFamily;
  readonly ip?: string;
  readonly asn?: string;
  readonly country?: string;
  readonly organization?: string;
}

export interface ProbeResult {
  readonly status: ProbeStatus;
  readonly target: ProxyTarget | null;
  readonly exitFamily: ExitFamily;
  readonly exits: readonly ProbeExit[];
  readonly endpoint?: string;
  readonly exitIp?: string;
  readonly latencyMs?: number;
  readonly code?: string;
  readonly message?: string;
}

type ProbeDetails = Omit<ProbeResult, 'status' | 'target' | 'exitFamily' | 'exits'> & {
  readonly exitFamily?: ExitFamily;
  readonly exits?: readonly ProbeExit[];
};

export function alive(target: ProxyTarget, details: ProbeDetails = {}): ProbeResult {
  return withOptionalDetails({ status: 'alive', target, exitFamily: details.exitFamily ?? 'unknown' }, details);
}

export function dead(target: ProxyTarget, details: ProbeDetails = {}): ProbeResult {
  return withOptionalDetails({ status: 'dead', target, exitFamily: 'unknown' }, details);
}

export function unknown(
  target: ProxyTarget | null,
  code: string,
  message: string,
  details: ProbeDetails = {},
): ProbeResult {
  return withOptionalDetails({ status: 'unknown', target, exitFamily: 'unknown', code, message }, details);
}

/**
 * "未知态"里只有这两类不是检测异常：从未探测过，以及 DNS 内容本身无法解析。
 * 其余未知态（超时、HTTP、网络异常、响应无法解析、未配置、主动取消……）都算检测接口异常，
 * 这样以后新增错误码时会默认落到"提示用户"而不是被静默忽略。
 */
const NON_PROBE_ERROR_CODES = new Set(['NOT_PROBED', 'INVALID_DNS_VALUE']);

export function isProbeErrorResult(result: ProbeResult): boolean {
  return result.status === 'unknown' && !NON_PROBE_ERROR_CODES.has(result.code ?? '');
}

export function exitFamilyFromIp(ip: string | undefined): ExitFamily {
  if (!ip) return 'unknown';
  if (looksLikeIpv4(ip)) return 'ipv4';
  if (ip.includes(':')) return 'ipv6';
  return 'unknown';
}

function withOptionalDetails(base: Omit<ProbeResult, 'exits'>, details: ProbeDetails): ProbeResult {
  return {
    ...base,
    exits: details.exits ? [...details.exits] : [],
    ...(details.endpoint ? { endpoint: details.endpoint } : {}),
    ...(details.exitIp ? { exitIp: details.exitIp } : {}),
    ...(typeof details.latencyMs === 'number' ? { latencyMs: details.latencyMs } : {}),
    ...(details.code ? { code: details.code } : {}),
    ...(details.message ? { message: details.message } : {}),
  };
}

function looksLikeIpv4(value: string): boolean {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  return value.split('.').every((part) => Number(part) <= 255);
}
