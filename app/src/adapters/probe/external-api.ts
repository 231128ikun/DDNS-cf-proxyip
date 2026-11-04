import { asRecord } from '../../contracts/parse';
import {
  alive,
  dead,
  exitFamilyFromIp,
  unknown,
  type ExitFamily,
  type ProbeExit,
  type ProbeResult,
  type ProbeDiagnostic,
} from '../../domain/probe-result';
import type { ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../../ports/probe';
import { createRequestTimeout } from '../../util/request-timeout';
import { appFetch } from '../../util/fetch';
import { createProbeRedactor, probeErrorMessage, probeResponseShape } from './diagnostics';
import {
  firstText,
  readProbeExit,
  readText,
  uniqueExits,
  type JsonRecord,
} from './probe-payload';

export interface ExternalApiProbeEndpoint {
  readonly name: string;
  readonly urlTemplate: string;
  readonly timeoutMs?: number;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface ProbeFailureDiagnostic extends ProbeDiagnostic {
  readonly target: string;
  readonly attempt: number;
  readonly phase: 'request' | 'body' | 'payload';
  readonly latencyMs: number;
  readonly httpStatus?: number;
  readonly contentType?: string;
  readonly responseShape?: string;
}

export interface ExternalApiProbeOptions {
  readonly endpoints: readonly ExternalApiProbeEndpoint[];
  readonly timeoutMs: number;
  readonly fallbackToNext?: boolean;
  readonly fetchImpl?: typeof fetch;
  readonly onDiagnostic?: (diagnostic: ProbeFailureDiagnostic) => void;
}

export class ExternalApiProbeAdapter implements ProbeAdapter {
  readonly name = 'external-api';

  private readonly endpoints: readonly ExternalApiProbeEndpoint[];
  private readonly timeoutMs: number;
  private readonly fallbackToNext: boolean;
  private readonly fetchImpl: typeof fetch;
  private readonly redact: (value: string) => string;
  private readonly onDiagnostic: ((diagnostic: ProbeFailureDiagnostic) => void) | undefined;

  constructor(options: ExternalApiProbeOptions) {
    if (options.endpoints.length === 0) throw new Error('external-api probe requires at least one endpoint');
    this.endpoints = options.endpoints;
    this.timeoutMs = options.timeoutMs;
    this.fallbackToNext = options.fallbackToNext ?? true;
    this.fetchImpl = options.fetchImpl ?? appFetch;
    this.redact = createProbeRedactor(options.endpoints);
    this.onDiagnostic = options.onDiagnostic;
  }

  async probe(target: ProxyTarget, context: ProbeContext = {}): Promise<ProbeResult> {
    const endpoints = this.endpoints.length === 1 && this.fallbackToNext
      ? [this.endpoints[0]!, this.endpoints[0]!]
      : this.endpoints;
    let result: ProbeResult | undefined;
    const diagnostics: ProbeDiagnostic[] = [];
    const finish = (value: ProbeResult): ProbeResult => diagnostics.length ? { ...value, diagnostics } : value;

    for (const [index, endpoint] of endpoints.entries()) {
      if (context.signal?.aborted) return unknown(target, 'CANCELLED', '检测已取消', { endpoint: endpoint.name });
      const checked = await this.probeEndpoint(target, endpoint, context, index + 1);
      result = checked.result;
      if (context.signal?.aborted) return unknown(target, 'CANCELLED', '检测已取消', { endpoint: endpoint.name });
      if (checked.diagnostic) {
        const { endpoint, status, code, message } = checked.diagnostic;
        diagnostics.push({ endpoint, status, ...(code ? { code } : {}), message });
        try { this.onDiagnostic?.(checked.diagnostic); }
        catch { console.warn('Probe diagnostic logger failed'); }
      }
      if (result.status === 'alive' || !this.fallbackToNext) return finish(result);
    }
    // 最后一次异常不能被此前的失效结论覆盖，之前的异常仍保留供排查。
    return finish(result ?? unknown(target, 'NO_ENDPOINT', '没有可用的检测接口'));
  }

  private async probeEndpoint(target: ProxyTarget, endpoint: ExternalApiProbeEndpoint, context: ProbeContext, attempt: number): Promise<{ result: ProbeResult; diagnostic?: ProbeFailureDiagnostic }> {
    const startedAt = Date.now();
    const timeout = createRequestTimeout(endpoint.timeoutMs ?? this.timeoutMs, context.signal);
    let phase: ProbeFailureDiagnostic['phase'] = 'request';
    let httpStatus: number | undefined;
    let contentType: string | undefined;
    let responseShape: string | undefined;
    const finish = (value: ProbeResult): { result: ProbeResult; diagnostic?: ProbeFailureDiagnostic } => {
      const result = value.message ? { ...value, message: this.redact(value.message) } : value;
      if (result.code === 'CANCELLED' || (result.status !== 'unknown' && result.code !== 'TIMEOUT' && result.code !== 'PARTIAL_EXIT')) return { result };
      return { result, diagnostic: { target: target.authority, endpoint: endpoint.name, attempt, phase,
        status: result.status, ...(result.code ? { code: result.code } : {}), message: result.message ?? result.code ?? '检测异常', latencyMs: Date.now() - startedAt,
        ...(httpStatus === undefined ? {} : { httpStatus }), ...(contentType ? { contentType } : {}), ...(responseShape ? { responseShape } : {}),
      } };
    };
    try {
      const url = buildProbeUrl(endpoint.urlTemplate, target);
      const init: RequestInit = { method: 'GET', signal: timeout.signal };
      if (endpoint.headers) init.headers = endpoint.headers;
      const response = await this.fetchImpl(url, init);
      httpStatus = response.status;
      const mime = response.headers.get('content-type')?.split(';')[0]?.trim();
      contentType = ['application/json', 'text/html', 'text/plain'].includes(mime ?? '') ? mime : mime ? 'other' : undefined;
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        return finish(unknown(target, 'HTTP_ERROR', `检测接口 HTTP ${response.status}`, { endpoint: endpoint.name, latencyMs: Date.now() - startedAt }));
      }
      phase = 'body';
      const text = await response.text();
      phase = 'payload';
      let payload: unknown;
      try { payload = JSON.parse(text); }
      catch {
        responseShape = (text.trim() ? /^\s*</.test(text) ? 'HTML' : 'non-JSON' : 'empty') + '(' + text.length + ')';
        return finish(unknown(target, 'INVALID_JSON', '检测接口返回的 JSON 无法解析：' + responseShape,
          { endpoint: endpoint.name, latencyMs: Date.now() - startedAt }));
      }
      responseShape = probeResponseShape(payload);
      return finish(parseProbePayload(payload, target, endpoint.name, Date.now() - startedAt));
    } catch (error) {
      const latencyMs = Date.now() - startedAt;
      if (context.signal?.aborted) return finish(unknown(target, 'CANCELLED', '检测已取消', { endpoint: endpoint.name, latencyMs }));
      if (timeout.didTimeout() || isTimeoutError(error)) {
        return finish(dead(target, { code: 'TIMEOUT', message: `检测超时 (${endpoint.timeoutMs ?? this.timeoutMs}ms)`, endpoint: endpoint.name, latencyMs }));
      }
      return finish(unknown(target, 'NETWORK_ERROR', '检测接口网络异常：' + probeErrorMessage(error), { endpoint: endpoint.name, latencyMs }));
    } finally { timeout.cleanup(); }
  }
}

export function buildProbeUrl(urlTemplate: string, target: ProxyTarget): string {
  const encoded = encodeURIComponent(target.authority);
  return urlTemplate.includes('{proxyip}') ? urlTemplate.replaceAll('{proxyip}', encoded) : `${urlTemplate}${encoded}`;
}

function parseProbePayload(payload: unknown, target: ProxyTarget, endpoint: string, latencyMs: number): ProbeResult {
  const record = unwrapPayload(payload);
  if (!record) return unknown(target, 'INVALID_RESPONSE', '检测接口响应不是对象', { endpoint, latencyMs });
  const message = readMessage(record);
  if (!isRecognizedPayload(record)) return unknown(target, 'INVALID_RESPONSE', '检测接口响应格式不可识别'
    + (message ? '：' + message : '') + ' (' + probeResponseShape(payload) + ')', { endpoint, latencyMs });

  if (record.apiError === true) {
    return unknown(target, 'PROBE_API_ERROR', message ?? '检测接口报告异常（节点状态未知）', { endpoint, latencyMs });
  }
  const statusText = readText(record.status)?.toLowerCase();
  const decision = readBooleanDecision(record) ?? readStatusDecision(statusText)
    ?? readProbeResultsDecision(record.probe_results ?? record.probeResults ?? record.probes);
  const detectorFailure = decision !== true ? readDetectorFailure(record, message) : null;
  if (detectorFailure) return unknown(target, 'PROBE_API_ERROR', detectorFailure, { endpoint, latencyMs });
  const exits = readProbeExits(record);
  const exitIp = pickExitIp(record, exits);
  const exitFamily = pickExitFamily(record, exitIp, exits);
  const colo = pickColo(record);
  const details = { endpoint, latencyMs, ...(colo ? { colo } : {}) };
  const candidateFailure = readCandidateFailure(record, decision === false ? message : undefined);

  const globalError = readProbeInfrastructureError(record, false);
  if (decision === true && globalError) {
    return unknown(target, 'PROBE_API_ERROR', trimMessage(globalError) ?? '检测接口异常', { endpoint, latencyMs });
  }
  const probeRecords = readProbeRecords(record.probe_results ?? record.probeResults ?? record.probes);
  if (decision === true && probeRecords.length && !exits.length) {
    return unknown(target, 'PROBE_API_ERROR', message ?? '检测接口成功标记与探测结果不一致', { endpoint, latencyMs });
  }
  if (decision === true || exitIp) {
    return alive(target, {
      ...details,
      ...(candidateFailure && exits.length ? { code: 'PARTIAL_EXIT', message: '部分出口探测失败：' + candidateFailure.message } : {}),
      exitFamily: candidateFailure && exits.length ? pickExitFamily({}, exitIp, exits) : exitFamily,
      exits,
      ...(exitIp ? { exitIp } : {}),
    });
  }
  if (decision === false) {
    return dead(target, {
      ...details,
      ...(candidateFailure ? { code: candidateFailure.code, message: candidateFailure.message }
        : message ? { code: 'TARGET_FAILED', message } : { code: 'TARGET_FAILED', message: '候选探测失败' }),
    });
  }
  if (statusText === 'error' || statusText === 'invalid') {
    return unknown(target, 'API_ERROR', message ?? '检测接口返回错误', { endpoint, latencyMs });
  }
  if (globalError) return unknown(target, 'PROBE_API_ERROR', trimMessage(globalError) ?? '检测接口异常', { endpoint, latencyMs });
  return unknown(target, 'INVALID_RESPONSE', message ?? '检测接口未返回可信的成功或失败结论', details);
}

function unwrapPayload(payload: unknown): JsonRecord | null {
  if (Array.isArray(payload)) {
    if (payload.length !== 1) return null;
    return asRecord(payload[0]);
  }
  return asRecord(payload);
}

function isRecognizedPayload(record: JsonRecord): boolean {
  return [
    'success',
    'ok',
    'apiError',
    'status',
    'proxyIP',
    'proxy_ip',
    'probe_results',
    'exitIp',
    'exit_ip',
    'inferred_stack',
    'supports_ipv4',
    'supports_ipv6',
  ].some((key) => key in record);
}

function readBooleanDecision(record: JsonRecord): boolean | undefined {
  if (typeof record.success === 'boolean') return record.success;
  if (typeof record.ok === 'boolean') return record.ok;
  return undefined;
}

function readStatusDecision(status: string | undefined): boolean | undefined {
  if (!status) return undefined;
  if (['success', 'ok', 'alive', 'available', 'healthy', 'up'].includes(status)) return true;
  if (['failed', 'failure', 'dead', 'unavailable', 'down'].includes(status)) return false;
  return undefined;
}

interface ProbeRecord {
  readonly hint: string;
  readonly record: JsonRecord;
}

function readProbeRecords(value: unknown): readonly ProbeRecord[] {
  if (Array.isArray(value)) return value.flatMap((item, index) => {
    const record = asRecord(item);
    if (!record) return [];
    return [{ hint: readText(record.exit_family) ?? readText(record.ipType) ?? readText(record.probe_name) ?? String(index), record }];
  });
  const probes = asRecord(value);
  if (!probes) return [];
  return Object.entries(probes).flatMap(([hint, value]) => {
    const record = asRecord(value);
    return record ? [{ hint, record }] : [];
  });
}

function readProbeResultsDecision(value: unknown): boolean | undefined {
  const records = readProbeRecords(value).map(item => item.record);
  if (!records.length) return undefined;
  const values = records.map(probe => typeof probe.ok === 'boolean' ? probe.ok
    : typeof probe.success === 'boolean' ? probe.success : undefined).filter((ok): ok is boolean => ok !== undefined);
  if (values.includes(true)) return true;
  if (values.length && values.every(ok => !ok)) return false;
  return undefined;
}

interface CandidateFailure {
  readonly code: string;
  readonly message: string;
}

function readCandidateFailure(record: JsonRecord, fallback: string | undefined): CandidateFailure | null {
  const failed = readProbeRecords(record.probe_results ?? record.probeResults ?? record.probes)
    .map(item => item.record).filter(isFailedProbe);
  const statuses = [...new Set(failed.map(probe => Number(probe.status_code))
    .filter(status => Number.isInteger(status) && status >= 100 && status <= 599))];
  const errors = [...new Set(failed.map(readProbeError).filter((value): value is string => Boolean(value)))];
  const text = errors.join('；') || fallback;
  if (statuses.length) return { code: 'TARGET_HTTP_ERROR', message: '候选链路 HTTP ' + statuses.join('/') };
  if (!text) return failed.length ? { code: 'TARGET_FAILED', message: '候选探测失败' } : null;
  const http = text.match(PROBE_HTTP_ERROR_PATTERN);
  if (http) return { code: 'TARGET_HTTP_ERROR', message: '候选链路 HTTP ' + http[1] };
  if (/time(?:d)?[ -]?out|timeout|etimedout/i.test(text)) return { code: 'TIMEOUT', message: '候选连接超时' };
  if (PROBE_TLS_ERROR_PATTERN.test(text)) return { code: 'TARGET_TLS_ERROR', message: trimMessage(text) ?? '候选 TLS 探测失败' };
  if (/tcp loop|tcp connect|network connection lost|connection reset|socket hang up|econnreset|eai_again|getaddrinfo|fetch failed|failed to fetch/i.test(text)) {
    return { code: 'TARGET_CONNECT_ERROR', message: trimMessage(text) ?? '候选连接失败' };
  }
  return { code: 'TARGET_FAILED', message: trimMessage(text) ?? '候选探测失败' };
}

function readDetectorFailure(record: JsonRecord, message: string | undefined): string | null {
  const topLevel = firstText(record, ['message', 'errorMessage', 'detail', 'reason']);
  const error = typeof record.error === 'string' ? record.error : undefined;
  const text = [topLevel, error, message].filter(Boolean).join(' ');
  if (!text) return null;
  if (/worker exceeded (?:cpu time|resource) limits?|too many subrequests|out of memory|rate limit|too many requests|quota exceeded|fetch failed:\s*internal/i.test(text)) {
    return trimMessage(text) ?? '检测接口异常';
  }
  return null;
}

function isFailedProbe(probe: JsonRecord): boolean {
  return probe.apiError === true || probe.ok === false || probe.success === false || Boolean(readProbeError(probe)) || ['error', 'invalid', 'failed', 'failure', 'dead', 'down']
    .includes(readText(probe.status)?.toLowerCase() ?? '');
}

function readProbeError(probe: JsonRecord): string | undefined {
  return firstText(probe, ['error', 'message', 'detail', 'reason']);
}

function pickExitIp(record: JsonRecord, exits: readonly ProbeExit[]): string | undefined {
  const fromExits = exits.find((exit) => exit.ip)?.ip;
  if (fromExits) return fromExits;

  const direct = firstText(record, ['exitIp', 'exit_ip', 'ipAddress']);
  if (direct) return direct;

  const exit = asRecord(record.exit);
  if (exit) {
    const fromExit = firstText(exit, ['ip', 'ipAddress', 'exitIp', 'exit_ip']);
    if (fromExit) return fromExit;
  } else if (typeof record.exit === 'string' && record.exit) {
    return record.exit;
  }

  const candidate = readText(record.proxyIP) ?? readText(record.proxy_ip);
  const topLevelIp = readText(record.ip);
  if (topLevelIp && topLevelIp !== candidate) return topLevelIp;

  for (const { record: probe } of readProbeRecords(record.probe_results ?? record.probeResults ?? record.probes)) {
    if (!isSuccessfulProbe(probe)) continue;
    const probeExit = asRecord(probe.exit);
    const fromProbe = probeExit ? firstText(probeExit, ['ip', 'ipAddress', 'exitIp', 'exit_ip']) : firstText(probe, ['exitIp', 'exit_ip']);
    if (fromProbe) return fromProbe;
  }
  return undefined;
}

function readProbeExits(record: JsonRecord, healthyOnly = false): readonly ProbeExit[] {
  const exits: ProbeExit[] = [];
  for (const { hint, record: probe } of readProbeRecords(record.probe_results ?? record.probeResults ?? record.probes)) {
    if (!isSuccessfulProbe(probe) || (healthyOnly && readProbeInfrastructureError(probe))) continue;
    const exit = asRecord(probe.exit) ?? asRecord(probe.egress) ?? asRecord(probe.result) ?? probe;
    const parsed = readProbeExit(exit, readText(probe.exit_family) ?? hint);
    if (parsed) exits.push(parsed);
  }
  if (healthyOnly) return uniqueExits(exits);
  for (const value of Array.isArray(record.exits) ? record.exits : []) {
    const exit = asRecord(value);
    if (!exit) continue;
    const parsed = readProbeExit(exit, readText(exit.stack) ?? readText(exit.ipType));
    if (parsed) exits.push(parsed);
  }
  const directExit = asRecord(record.exit) ?? asRecord(record.egress);
  if (directExit) {
    const parsed = readProbeExit(directExit, readText(record.stack) ?? readText(record.ipType));
    if (parsed) exits.push(parsed);
  }
  return uniqueExits(exits);
}

function isSuccessfulProbe(probe: JsonRecord): boolean {
  if (probe.apiError === true || probe.ok === false || probe.success === false || readProbeError(probe)
    || ['error', 'invalid'].includes(readText(probe.status)?.toLowerCase() ?? '')
    || readStatusDecision(readText(probe.status)?.toLowerCase()) === false) return false;
  return probe.ok === true || probe.success === true || readText(probe.status)?.toLowerCase() === 'success' || asRecord(probe.exit) !== null;
}

function pickExitFamily(record: JsonRecord, exitIp: string | undefined, exits: readonly ProbeExit[]): ExitFamily {
  const stack = (readText(record.inferred_stack) ?? readText(record.stack) ?? readText(record.ipType) ?? '').toLowerCase();
  if (stack === 'dual_stack' || stack === 'dual' || stack === 'v4/v6') return 'dual';
  if (stack === 'ipv4_only' || stack === 'ipv4' || stack === 'v4') return 'ipv4';
  if (stack === 'ipv6_only' || stack === 'ipv6' || stack === 'v6') return 'ipv6';

  const supportsIpv4 = record.supports_ipv4 === true;
  const supportsIpv6 = record.supports_ipv6 === true;
  if (supportsIpv4 && supportsIpv6) return 'dual';
  if (supportsIpv4) return 'ipv4';
  if (supportsIpv6) return 'ipv6';

  const hasIpv4 = exits.some(exit => exit.family === 'ipv4');
  const hasIpv6 = exits.some(exit => exit.family === 'ipv6');
  if (hasIpv4 && hasIpv6) return 'dual';
  if (hasIpv4) return 'ipv4';
  if (hasIpv6) return 'ipv6';
  return exitFamilyFromIp(exitIp);
}

function pickColo(record: JsonRecord): string | undefined {
  const direct = readText(record.colo)?.toUpperCase();
  if (direct && /^[A-Z]{3}$/.test(direct)) return direct;
  for (const { record: probe } of readProbeRecords(record.probe_results ?? record.probeResults ?? record.probes)) {
    if (!isSuccessfulProbe(probe)) continue;
    const value = firstText(probe, ['exit_colo', 'colo']) ?? firstText(asRecord(probe.exit) ?? {}, ['colo']);
    const normalized = value?.toUpperCase();
    if (normalized && /^[A-Z]{3}$/.test(normalized)) return normalized;
  }
  return undefined;
}

function readProbeInfrastructureError(record: JsonRecord, includeProbes = true): string | undefined {
  const messageKeys = ['message', 'errorMessage', 'detail', 'reason', 'error'];
  // 检查所有错误别名及嵌套消息，只匹配实际字符串，不把计时字段、空 error 或出口元数据当作错误。
  for (const key of [...messageKeys, ...(includeProbes ? ['probe_results', 'probeResults', 'probes'] : [])]) {
    const pending = [{ value: record[key], isMessage: messageKeys.includes(key) }];
    while (pending.length) {
      const { value, isMessage } = pending.pop()!;
      if (typeof value === 'string') {
        if (isMessage && isProbeInfrastructureMessage(value)) return value;
      } else if (value && typeof value === 'object') {
        for (const [nestedKey, nestedValue] of Object.entries(value)) {
          pending.push({ value: nestedValue, isMessage: isMessage || messageKeys.includes(nestedKey) });
        }
      }
    }
  }
  return undefined;
}

const PROBE_INFRASTRUCTURE_ERROR_PATTERN =
  /tcp loop detected|contact us if this doesn't seem right|network connection lost|connection reset by peer|socket hang up|econnreset|etimedout|eai_again|getaddrinfo|time(?:d)?[ -]?out|timeout|worker exceeded (?:cpu time|resource) limits?|too many subrequests|out of memory|rate limit|too many requests|quota exceeded|bad gateway|service unavailable|internal server error|fetch failed|failed to fetch|invalid (?:probe )?response|malformed response|json parse|unexpected response|unexpected status:\s*[45]\d{2}|request cancel(?:l)?ed|operation aborted/i;

const PROBE_HTTP_ERROR_PATTERN = /\b(?:http(?:\s+(?:error|status))?|unexpected status|upstream(?: returned)?)\s*[:=]?\s*([45]\d{2})\b/i;
const PROBE_TLS_ERROR_PATTERN = /(?:tls|ssl).{0,80}(?:fail|error|alert)|handshake.{0,80}(?:fail|error)|certificate.{0,80}(?:expired|invalid|fail|error|verify)|(?:err_(?:ssl|tls|cert)|ssl_error|cert_has_expired|unable_to_verify_leaf_signature|depth_zero_self_signed_cert)|(?:self[ -]signed|unable to verify).*certificate/i;

function isProbeInfrastructureMessage(value: string): boolean {
  return PROBE_INFRASTRUCTURE_ERROR_PATTERN.test(value)
    || PROBE_HTTP_ERROR_PATTERN.test(value)
    || PROBE_TLS_ERROR_PATTERN.test(value);
}

function readMessage(record: JsonRecord): string | undefined {
  const direct = firstText(record, ['message', 'errorMessage', 'detail', 'reason']);
  if (direct) return trimMessage(direct);
  const error = record.error;
  if (typeof error === 'string') return trimMessage(error);
  const errorRecord = asRecord(error);
  return errorRecord ? trimMessage(firstText(errorRecord, ['message', 'detail', 'code']) ?? '') : undefined;
}

function trimMessage(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 240) : undefined;
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && error.name === 'TimeoutError';
}
