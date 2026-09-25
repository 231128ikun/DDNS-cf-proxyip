import { asRecord } from '../../contracts/parse';
import {
  alive,
  dead,
  exitFamilyFromIp,
  unknown,
  type ExitFamily,
  type ProbeExit,
  type ProbeResult,
} from '../../domain/probe-result';
import type { ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../../ports/probe';
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

export interface ExternalApiProbeOptions {
  readonly endpoints: readonly ExternalApiProbeEndpoint[];
  readonly timeoutMs: number;
  readonly fallbackToNext?: boolean;
  readonly fetchImpl?: typeof fetch;
}

export class ExternalApiProbeAdapter implements ProbeAdapter {
  readonly name = 'external-api';

  private readonly endpoints: readonly ExternalApiProbeEndpoint[];
  private readonly timeoutMs: number;
  private readonly fallbackToNext: boolean;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ExternalApiProbeOptions) {
    if (options.endpoints.length === 0) throw new Error('external-api probe requires at least one endpoint');
    this.endpoints = options.endpoints;
    this.timeoutMs = options.timeoutMs;
    this.fallbackToNext = options.fallbackToNext ?? true;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async probe(target: ProxyTarget, context: ProbeContext = {}): Promise<ProbeResult> {
    const attempts: ProbeResult[] = [];

    for (const endpoint of this.endpoints) {
      const result = await this.probeEndpoint(target, endpoint, context);
      attempts.push(result);
      if (result.status === 'alive') return result;
      if (!this.fallbackToNext) return result;
      if (context.signal?.aborted) return result;
    }

    return attempts.find((result) => result.status === 'dead') ?? attempts.at(-1) ?? unknown(target, 'NO_ENDPOINT', '没有可用的检测接口');
  }

  private async probeEndpoint(target: ProxyTarget, endpoint: ExternalApiProbeEndpoint, context: ProbeContext): Promise<ProbeResult> {
    const startedAt = Date.now();
    const timeout = createRequestTimeout(endpoint.timeoutMs ?? this.timeoutMs, context.signal);

    try {
      const url = buildProbeUrl(endpoint.urlTemplate, target);
      const init: RequestInit = { method: 'GET', signal: timeout.signal };
      if (endpoint.headers) init.headers = endpoint.headers;

      const response = await this.fetchImpl(url, init);
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        return unknown(target, 'HTTP_ERROR', `检测接口 HTTP ${response.status}`, {
          endpoint: endpoint.name,
          latencyMs: Date.now() - startedAt,
        });
      }

      const text = await response.text();
      let payload: unknown;
      try {
        payload = JSON.parse(text);
      } catch {
        return unknown(target, 'INVALID_JSON', '检测接口返回的 JSON 无法解析', {
          endpoint: endpoint.name,
          latencyMs: Date.now() - startedAt,
        });
      }

      return parseProbePayload(payload, target, endpoint.name, Date.now() - startedAt);
    } catch (error) {
      const latencyMs = Date.now() - startedAt;
      if (context.signal?.aborted) {
        return unknown(target, 'CANCELLED', '检测已取消', { endpoint: endpoint.name, latencyMs });
      }
      if (timeout.didTimeout() || isAbortError(error)) {
        return unknown(target, 'TIMEOUT', `检测超时 (${endpoint.timeoutMs ?? this.timeoutMs}ms)`, {
          endpoint: endpoint.name,
          latencyMs,
        });
      }
      return unknown(target, 'NETWORK_ERROR', '检测接口网络异常', {
        endpoint: endpoint.name,
        latencyMs,
      });
    } finally {
      timeout.cleanup();
    }
  }
}

export function buildProbeUrl(urlTemplate: string, target: ProxyTarget): string {
  const encoded = encodeURIComponent(target.authority);
  return urlTemplate.includes('{proxyip}') ? urlTemplate.replaceAll('{proxyip}', encoded) : `${urlTemplate}${encoded}`;
}

function createRequestTimeout(timeoutMs: number, externalSignal?: AbortSignal): {
  signal: AbortSignal;
  didTimeout: () => boolean;
  cleanup: () => void;
} {
  const controller = new AbortController();
  let timedOut = false;
  const handleExternalAbort = () => controller.abort(externalSignal?.reason);
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  if (externalSignal?.aborted) handleExternalAbort();
  else externalSignal?.addEventListener('abort', handleExternalAbort, { once: true });

  return {
    signal: controller.signal,
    didTimeout: () => timedOut,
    cleanup: () => {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', handleExternalAbort);
    },
  };
}

function parseProbePayload(payload: unknown, target: ProxyTarget, endpoint: string, latencyMs: number): ProbeResult {
  const record = unwrapPayload(payload);
  if (!record) return unknown(target, 'INVALID_RESPONSE', '检测接口响应不是对象', { endpoint, latencyMs });
  if (!isRecognizedPayload(record)) return unknown(target, 'INVALID_RESPONSE', '检测接口响应格式不可识别', { endpoint, latencyMs });

  const statusText = readText(record.status)?.toLowerCase();
  if (statusText === 'error' || statusText === 'invalid') {
    return unknown(target, 'API_ERROR', readMessage(record) ?? '检测接口返回错误', { endpoint, latencyMs });
  }

  const decision = readBooleanDecision(record) ?? readStatusDecision(statusText) ?? readProbeResultsDecision(record.probe_results);
  const exits = readProbeExits(record);
  const exitIp = pickExitIp(record, exits);
  const exitFamily = pickExitFamily(record, exitIp);
  const message = readMessage(record);

  if (decision === true) {
    return alive(target, {
      endpoint,
      latencyMs,
      exitFamily,
      exits,
      ...(exitIp ? { exitIp } : {}),
    });
  }
  if (decision === false) {
    return dead(target, {
      endpoint,
      latencyMs,
      ...(message ? { message } : {}),
    });
  }
  if (exitIp) {
    return alive(target, {
      endpoint,
      latencyMs,
      exitFamily,
      exits,
      exitIp,
    });
  }

  return unknown(target, 'INVALID_RESPONSE', message ?? '检测接口未返回可信的成功或失败结论', {
    endpoint,
    latencyMs,
  });
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

function readProbeResultsDecision(value: unknown): boolean | undefined {
  const probes = asRecord(value);
  if (!probes) return undefined;
  const values = Object.values(probes).map(asRecord).filter((probe): probe is JsonRecord => probe !== null);
  if (values.length === 0) return undefined;
  const okValues = values.map((probe) => probe.ok).filter((ok): ok is boolean => typeof ok === 'boolean');
  if (okValues.includes(true)) return true;
  if (okValues.length > 0 && okValues.every((ok) => !ok)) return false;
  return undefined;
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

  const probes = asRecord(record.probe_results);
  if (!probes) return undefined;
  for (const probeValue of Object.values(probes)) {
    const probe = asRecord(probeValue);
    if (!probe) continue;
    const probeExit = asRecord(probe.exit);
    const fromProbe = probeExit ? firstText(probeExit, ['ip', 'ipAddress', 'exitIp', 'exit_ip']) : firstText(probe, ['exitIp', 'exit_ip']);
    if (fromProbe) return fromProbe;
  }
  return undefined;
}

function readProbeExits(record: JsonRecord): readonly ProbeExit[] {
  const exits: ProbeExit[] = [];
  const probes = asRecord(record.probe_results) ?? asRecord(record.probeResults) ?? asRecord(record.probes);

  if (probes) {
    for (const [stack, value] of Object.entries(probes)) {
      const probe = asRecord(value);
      if (!probe || !isSuccessfulProbe(probe)) continue;
      const exit = asRecord(probe.exit) ?? asRecord(probe.egress) ?? asRecord(probe.result) ?? probe;
      const parsed = readProbeExit(exit, stack);
      if (parsed) exits.push(parsed);
    }
  }

  const directValues = Array.isArray(record.exits) ? record.exits : [];
  for (const value of directValues) {
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
  return probe.ok === true || probe.success === true || readText(probe.status)?.toLowerCase() === 'success' || asRecord(probe.exit) !== null;
}





function pickExitFamily(record: JsonRecord, exitIp: string | undefined): ExitFamily {
  const stack = (readText(record.inferred_stack) ?? readText(record.stack) ?? readText(record.ipType) ?? '').toLowerCase();
  if (stack === 'dual_stack' || stack === 'dual' || stack === 'v4/v6') return 'dual';
  if (stack === 'ipv4_only' || stack === 'ipv4' || stack === 'v4') return 'ipv4';
  if (stack === 'ipv6_only' || stack === 'ipv6' || stack === 'v6') return 'ipv6';

  const supportsIpv4 = record.supports_ipv4 === true;
  const supportsIpv6 = record.supports_ipv6 === true;
  if (supportsIpv4 && supportsIpv6) return 'dual';
  if (supportsIpv4) return 'ipv4';
  if (supportsIpv6) return 'ipv6';

  return exitFamilyFromIp(exitIp);
}

function readMessage(record: JsonRecord): string | undefined {
  const direct = firstText(record, ['message', 'errorMessage']);
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




function isAbortError(error: unknown): boolean {
  return error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name);
}
