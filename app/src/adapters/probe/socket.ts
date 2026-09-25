import { parseSocketProbeUrl, type SocketProbeUrl } from '../../contracts/config';
import { asRecord } from '../../contracts/parse';
import { alive, dead, unknown, type ExitFamily, type ProbeExit, type ProbeResult } from '../../domain/probe-result';
import type { ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../../ports/probe';
import { readProbeExit, uniqueExits } from './probe-payload';

/**
 * 双探针 Socket 适配器。
 *
 * 流程参考 CF-Workers-CheckProxyIP 的 `/check`：连上候选地址 → 发起 TLS →
 * 用探针服务自己的域名发 HTTP 请求 → 解析返回的出口 IP。
 * 差别是这里不再手写 TLS 客户端，而是复用 `cloudflare:sockets` 的 `startTls`，
 * 省掉上千行密码学代码；`connect` 由调用方注入，测试可以注入轻量假实现。
 */

/** 探针只用到 Socket 的这一部分能力，用窄接口是为了让测试假实现足够小。 */
export interface ProbeSocket {
  readonly opened: Promise<unknown>;
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  close(): Promise<void>;
  startTls(options?: TlsOptions): ProbeSocket;
}

export type SocketConnect = (address: SocketAddress, options: SocketOptions) => ProbeSocket;

export interface SocketProbeOptions {
  /** 探针服务地址，例如 https://ipv4.090227.xyz/；留空表示该族探针未配置。 */
  readonly ipv4Url: string;
  readonly ipv6Url: string;
  readonly timeoutMs: number;
  readonly readLimitBytes: number;
  readonly connect: SocketConnect;
}

type ProbeFailure = 'CANCELLED' | 'TIMEOUT' | 'REFUSED' | 'NETWORK_ERROR' | 'INVALID_RESPONSE';

interface ProbeTarget {
  /** 探针服务域名：同时用于 TLS SNI、Host 头和结果说明。 */
  readonly endpoint: string;
  readonly request: Uint8Array;
}

type ProbeAttempt =
  | { readonly ok: true; readonly exit: ProbeExit; readonly statusCode: number; readonly latencyMs: number; readonly endpoint: string }
  | { readonly ok: false; readonly failure: ProbeFailure; readonly message: string; readonly latencyMs: number; readonly endpoint: string };

type FailedAttempt = Extract<ProbeAttempt, { ok: false }>;

type ProbeResponse =
  | { readonly ok: true; readonly exit: ProbeExit; readonly statusCode: number }
  | { readonly ok: false; readonly message: string; readonly statusCode?: number };

export class SocketProbeAdapter implements ProbeAdapter {
  readonly name = 'socket';

  private readonly targets: readonly ProbeTarget[];
  private readonly timeoutMs: number;
  private readonly readLimitBytes: number;
  private readonly connect: SocketConnect;

  constructor(options: SocketProbeOptions) {
    this.targets = [options.ipv4Url, options.ipv6Url]
      .map(buildTarget)
      .filter((target): target is ProbeTarget => target !== null);
    this.timeoutMs = options.timeoutMs;
    this.readLimitBytes = options.readLimitBytes;
    this.connect = options.connect;
  }

  async probe(target: ProxyTarget, context: ProbeContext = {}): Promise<ProbeResult> {
    if (this.targets.length === 0) {
      return unknown(target, 'NOT_CONFIGURED', '未配置 IPv4/IPv6 Socket 探针地址');
    }
    if (context.signal?.aborted) return cancelled(target);

    // 两个探针并行，任一成功即视为可用；两者都失败时再按失败类型区分 dead / unknown。
    const attempts = await Promise.all(this.targets.map((probe) => this.runProbe(probe, target, context)));
    return combineAttempts(target, attempts);
  }

  private async runProbe(probe: ProbeTarget, target: ProxyTarget, context: ProbeContext): Promise<ProbeAttempt> {
    const startedAt = Date.now();
    let live: ProbeSocket | null = null;

    try {
      const connection = this.connect({ hostname: connectHostname(target), port: target.port }, { secureTransport: 'starttls', allowHalfOpen: true });
      live = connection;

      const response = await withDeadline(async () => {
        await connection.opened;
        const tls = connection.startTls({ expectedServerHostname: probe.endpoint });
        live = tls;
        await tls.opened;
        return parseResponse(await exchange(tls, probe.request, this.readLimitBytes));
      }, this.timeoutMs, context.signal);

      const latencyMs = Date.now() - startedAt;
      if (response.ok) {
        return { ok: true, exit: response.exit, statusCode: response.statusCode, latencyMs, endpoint: probe.endpoint };
      }
      return { ok: false, failure: 'INVALID_RESPONSE', message: response.message, latencyMs, endpoint: probe.endpoint };
    } catch (error) {
      const failure = classifyError(error, context.signal);
      return {
        ok: false,
        failure,
        message: describeFailure(failure, error),
        latencyMs: Date.now() - startedAt,
        endpoint: probe.endpoint,
      };
    } finally {
      await closeQuietly(live);
    }
  }
}

/** 把单次探针结果合并成统一的三态结论：unknown 永远不会被解释成节点失效。 */
function combineAttempts(target: ProxyTarget, attempts: readonly ProbeAttempt[]): ProbeResult {
  const succeeded = attempts.filter((attempt) => attempt.ok);
  const latencyMs = Math.min(...attempts.map((attempt) => attempt.latencyMs));

  if (succeeded.length > 0) {
    const exits = uniqueExits(succeeded.map((attempt) => attempt.exit));
    const exitIp = exits.find((exit) => exit.family === 'ipv4')?.ip ?? exits[0]?.ip;
    return alive(target, {
      endpoint: 'socket',
      exitFamily: familyFromExits(exits),
      exits,
      ...(exitIp ? { exitIp } : {}),
      latencyMs,
    });
  }

  const failed = attempts.filter((attempt): attempt is FailedAttempt => !attempt.ok);
  const failure = dominantFailure(failed);
  const message = failed[0]?.message ?? 'Socket 探针未返回可用出口';

  // 只有全部探针都明确"连接被拒绝"才判死；超时、TLS 失败、探针自身返回异常一律保持 unknown。
  if (failure === 'REFUSED') {
    return dead(target, { endpoint: 'socket', latencyMs, message: '两个 Socket 探针都无法连接候选地址' });
  }
  return unknown(target, failure, message, { endpoint: 'socket', latencyMs });
}

function dominantFailure(failed: readonly FailedAttempt[]): ProbeFailure {
  const kinds = new Set(failed.map((attempt) => attempt.failure));
  if (kinds.size === 1) return failed[0]?.failure ?? 'NETWORK_ERROR';
  // 失败类型混杂（例如 IPv4 超时、IPv6 被拒绝）说明结论不可信，按网络异常处理。
  return kinds.has('CANCELLED') ? 'CANCELLED' : 'NETWORK_ERROR';
}

function familyFromExits(exits: readonly ProbeExit[]): ExitFamily {
  const families = new Set(exits.map((exit) => exit.family));
  const hasIpv4 = families.has('ipv4');
  const hasIpv6 = families.has('ipv6');
  if (hasIpv4 && hasIpv6) return 'dual';
  if (hasIpv4) return 'ipv4';
  if (hasIpv6) return 'ipv6';
  return 'unknown';
}

function buildTarget(url: string): ProbeTarget | null {
  const parsed = parseSocketProbeUrl(url);
  if (!parsed) return null;
  return { endpoint: parsed.endpoint, request: buildRequest(parsed) };
}

/** 参考实现用方括号包裹 IPv6 字面量，而 `ProxyTarget.host` 不带括号。 */
function connectHostname(target: ProxyTarget): string {
  return target.family === 'ipv6' ? `[${target.host}]` : target.host;
}

/**
 * 探针服务走 Cloudflare，非浏览器 UA 可能被拦，
 * 因此沿用参考实现的浏览器 UA，只保留必要的请求头。
 */
function buildRequest(parsed: SocketProbeUrl): Uint8Array {
  const request = [
    `GET ${parsed.path} HTTP/1.1`,
    `Host: ${parsed.hostHeader}`,
    'Accept: application/json, text/plain, */*',
    'Accept-Encoding: identity',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Connection: close',
    '',
    '',
  ].join('\r\n');
  return new TextEncoder().encode(request);
}

async function exchange(tls: ProbeSocket, request: Uint8Array, readLimitBytes: number): Promise<Uint8Array> {
  const writer = tls.writable.getWriter();
  try {
    await writer.write(request);
  } finally {
    writer.releaseLock();
  }
  return readLimited(tls.readable, readLimitBytes);
}

async function readLimited(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const remaining = limit - total;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  return concatBytes(chunks, total);
}

const HEADER_SEPARATOR = Uint8Array.of(13, 10, 13, 10);
const LINE_SEPARATOR = Uint8Array.of(13, 10);
const HTTP_STATUS_RE = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/;
const CHUNKED_RE = /transfer-encoding:\s*chunked/i;

function parseResponse(raw: Uint8Array): ProbeResponse {
  if (raw.byteLength === 0) return { ok: false, message: 'Socket 探针返回空响应' };

  const splitIndex = indexOfBytes(raw, HEADER_SEPARATOR);
  const headerText = decode(splitIndex < 0 ? raw : raw.subarray(0, splitIndex));
  const bodyBytes = splitIndex < 0 ? new Uint8Array(0) : raw.subarray(splitIndex + HEADER_SEPARATOR.byteLength);
  const statusCode = Number(HTTP_STATUS_RE.exec(headerText)?.[1] ?? 0);

  if (statusCode !== 200) {
    return { ok: false, message: `Socket 探针 HTTP 状态异常（${statusCode || 'unknown'}）`, ...(statusCode ? { statusCode } : {}) };
  }

  let body = bodyBytes;
  if (CHUNKED_RE.test(headerText)) {
    const decoded = decodeChunked(bodyBytes);
    if (!decoded) return { ok: false, message: 'Socket 探针响应分块数据不完整', statusCode };
    body = decoded;
  }

  let payload: unknown;
  try {
    payload = JSON.parse(decode(body));
  } catch {
    return { ok: false, message: 'Socket 探针响应不是合法 JSON', statusCode };
  }

  const exit = readProbeExit(asRecord(payload) ?? {}, undefined);
  if (!exit?.ip) return { ok: false, message: 'Socket 探针响应缺少出口 IP', statusCode };
  return { ok: true, exit, statusCode };
}

function decodeChunked(body: Uint8Array): Uint8Array | null {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  let total = 0;

  while (offset < body.byteLength) {
    const lineEnd = indexOfBytes(body, LINE_SEPARATOR, offset);
    if (lineEnd < 0) return null;
    const sizeHex = decode(body.subarray(offset, lineEnd)).split(';')[0]?.trim() ?? '';
    const size = Number.parseInt(sizeHex, 16);
    if (!Number.isFinite(size) || size < 0) return null;

    const bodyStart = lineEnd + LINE_SEPARATOR.byteLength;
    if (size === 0) return concatBytes(chunks, total);
    const bodyEnd = bodyStart + size;
    if (bodyEnd > body.byteLength) return null;

    const chunk = body.subarray(bodyStart, bodyEnd);
    chunks.push(chunk);
    total += chunk.byteLength;
    offset = bodyEnd + LINE_SEPARATOR.byteLength;
  }

  return null;
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, start = 0): number {
  const limit = haystack.byteLength - needle.byteLength;
  outer: for (let index = start; index <= limit; index += 1) {
    for (let offset = 0; offset < needle.byteLength; offset += 1) {
      if (haystack[index + offset] !== needle[offset]) continue outer;
    }
    return index;
  }
  return -1;
}

function concatBytes(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

class ProbeTimeoutError extends Error {}
class ProbeAbortedError extends Error {}

/** 单个探针的 connect + TLS + 读写合计超时；abort 与超时都通过拒绝当前 await 生效。 */
async function withDeadline<T>(work: () => Promise<T>, timeoutMs: number, externalSignal?: AbortSignal): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;

  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ProbeTimeoutError(`socket probe timeout after ${timeoutMs}ms`)), timeoutMs);
  });
  timeout.catch(() => undefined);
  const marks: Promise<never>[] = [timeout];

  if (externalSignal) {
    const aborted = new Promise<never>((_, reject) => {
      onAbort = () => reject(new ProbeAbortedError('socket probe aborted'));
      if (externalSignal.aborted) onAbort();
      else externalSignal.addEventListener('abort', onAbort, { once: true });
    });
    aborted.catch(() => undefined);
    marks.push(aborted);
  }

  try {
    return await Promise.race([work(), ...marks]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (onAbort) externalSignal?.removeEventListener('abort', onAbort);
  }
}

function classifyError(error: unknown, externalSignal?: AbortSignal): ProbeFailure {
  if (error instanceof ProbeTimeoutError) return 'TIMEOUT';
  if (error instanceof ProbeAbortedError || externalSignal?.aborted) return 'CANCELLED';
  if (isConnectionRefused(error)) return 'REFUSED';
  return 'NETWORK_ERROR';
}

/** 只把明确的"连接被拒绝"当作节点失效信号，其余错误都不能证明节点已死。 */
function isConnectionRefused(error: unknown): boolean {
  return error instanceof Error && /refused|ECONNREFUSED/i.test(error.message);
}

function describeFailure(failure: ProbeFailure, error: unknown): string {
  const detail = error instanceof Error ? trimMessage(error.message) : undefined;
  if (failure === 'CANCELLED') return '检测已取消';
  if (failure === 'TIMEOUT') return 'Socket 探针超时';
  if (failure === 'REFUSED') return 'Socket 探针连接被拒绝';
  if (failure === 'INVALID_RESPONSE') return detail ?? 'Socket 探针响应不可用';
  return detail ? `Socket 探针网络异常：${detail}` : 'Socket 探针网络异常';
}

function cancelled(target: ProxyTarget): ProbeResult {
  return unknown(target, 'CANCELLED', '检测已取消', { endpoint: 'socket' });
}

function trimMessage(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 160) : undefined;
}

async function closeQuietly(socket: ProbeSocket | null): Promise<void> {
  if (!socket) return;
  try {
    await socket.close();
  } catch {
    // 关闭失败不影响已经得到的结论。
  }
}