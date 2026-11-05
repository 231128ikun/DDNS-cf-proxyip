import type { ProxyTarget } from './proxy-target';

export type ProbeStatus = 'alive' | 'dead' | 'unknown';
export type ExitFamily = 'ipv4' | 'ipv6' | 'dual' | 'unknown';
export type SingleExitFamily = 'ipv4' | 'ipv6' | 'unknown';

export interface ProbeExit {
  readonly family: SingleExitFamily;
  readonly ip?: string;
  readonly asn?: string;
  readonly country?: string;
  readonly region?: string;
  readonly city?: string;
  readonly organization?: string;
}

export interface ProbeDiagnostic {
  readonly endpoint: string;
  readonly status: ProbeStatus;
  readonly code?: string;
  readonly message: string;
}

export interface ProbeResult {
  readonly status: ProbeStatus;
  readonly target: ProxyTarget | null;
  readonly exitFamily: ExitFamily;
  readonly exits: readonly ProbeExit[];
  readonly endpoint?: string;
  readonly exitIp?: string;
  readonly latencyMs?: number;
  readonly colo?: string;
  readonly code?: string;
  readonly message?: string;
  readonly diagnostics?: readonly ProbeDiagnostic[];
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

/** 未探测和无效 DNS 值不属于探针故障；其余 unknown 结果均计为检测接口异常。 */
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
    ...(details.colo ? { colo: details.colo } : {}),
    ...(details.code ? { code: details.code } : {}),
    ...(details.message ? { message: details.message } : {}),
    ...(details.diagnostics?.length ? { diagnostics: details.diagnostics } : {}),
  };
}

function looksLikeIpv4(value: string): boolean {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  return value.split('.').every((part) => Number(part) <= 255);
}
