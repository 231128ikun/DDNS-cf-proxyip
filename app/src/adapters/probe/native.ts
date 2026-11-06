import { asRecord } from '../../contracts/parse';
import { alive, dead, unknown, type ProbeExit, type ProbeResult } from '../../domain/probe-result';
import { parseProxyTarget, type ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../../ports/probe';
import { createRequestTimeout } from '../../util/request-timeout';
import { FetchBudgetError } from '../../util/fetch';
import { readProbeExit, readText, uniqueExits } from './probe-payload';
import { isSubrequestLimit, isTcpLoop } from './probe-errors';
import { createProbeRedactor, probeErrorMessage } from './diagnostics';
import { secureProbeSocket } from './tls';

export type ProbeSocket = Pick<Socket, 'opened' | 'closed' | 'readable' | 'writable' | 'close' | 'startTls'>;
export type ProbeConnect = (address: SocketAddress, options: SocketOptions) => ProbeSocket | Promise<ProbeSocket>;
interface NativeProbeOptions {
  readonly urls: readonly string[];
  readonly timeoutMs: number;
  readonly connect: ProbeConnect;
  readonly secure?: (socket: ProbeSocket, hostname: string) => Promise<ProbeSocket>;
  readonly backup?: ProbeAdapter;
  readonly rootsFetch?: typeof fetch;
}
const READ_LIMIT = 65_536;

/** 候选 TCP + 显式 SNI/Host；两个出口分支复用同一 TLS 适配器。 */
export class NativeProbeAdapter implements ProbeAdapter {
  readonly name = 'native';
  private active = 0;
  private waiting: (() => void)[] = [];
  private subrequestLimitReached = false;
  private readonly redact: (message: string) => string;
  constructor(private readonly options: NativeProbeOptions) {
    this.redact = createProbeRedactor(options.urls.map(urlTemplate => ({ name: 'native', urlTemplate })));
  }

  async probe(target: ProxyTarget, context: ProbeContext = {}): Promise<ProbeResult> {
    const first = await this.check(target, context);
    if (first.status === 'alive' || context.signal?.aborted || first.code === 'SUBREQUEST_LIMIT' || first.code === 'PROBE_BUDGET_EXHAUSTED') return first;
    const second = this.options.backup
      ? await this.limited(() => this.runAttempt(target, () => this.options.backup!.probe(target, context)), context.signal)
        ?? unknown(target, 'CANCELLED', '检测已取消')
      : await this.check(target, context);
    // 任一轮自身异常都不能凭另一轮的失败推断节点失效；明确成功可以恢复。
    if (second.status === 'alive') return second;
    return first.status === 'unknown' && second.status === 'dead' ? first : second;
  }

  private async runAttempt(target: ProxyTarget, task: () => Promise<ProbeResult>): Promise<ProbeResult> {
    if (this.subrequestLimitReached) return unknown(target, 'SUBREQUEST_LIMIT', 'Worker 子请求额度已用尽');
    const result = await task();
    if (result.code === 'SUBREQUEST_LIMIT') this.subrequestLimitReached = true;
    return result;
  }

  private async check(target: ProxyTarget, context: ProbeContext): Promise<ProbeResult> {
    if (context.signal?.aborted) return unknown(target, 'CANCELLED', '检测已取消');
    let urls: URL[];
    try {
      urls = this.options.urls.filter(Boolean).map(value => new URL(value));
      if (!urls.length || urls.some(url => url.protocol !== 'https:' || url.username || url.password || url.hash)) throw new Error();
    } catch { return unknown(target, 'NOT_CONFIGURED', '出口检测地址必须为 HTTPS JSON 接口'); }
    const connect = this.options.connect;
    const started = Date.now();
    const results = await Promise.all(urls.map(url => this.limited(
      () => this.runAttempt(target, () => this.checkExit(target, url, connect, context)), context.signal)));
    if (context.signal?.aborted) return unknown(target, 'CANCELLED', '检测已取消');
    const exits = uniqueExits(results.flatMap(result => result?.status === 'alive' ? result.exits : []));
    const failed = results.find(result => result && result.status !== 'alive');
    if (exits.length) {
      const families = new Set(exits.map(exit => exit.family));
      const colo = results.find(result => result?.status === 'alive' && result.colo)?.colo;
      return alive(target, { endpoint: this.name, latencyMs: Date.now() - started, exits,
        ...(colo ? { colo } : {}),
        exitIp: exits[0]!.ip!, exitFamily: families.size > 1 ? 'dual' : exits[0]!.family,
        ...(failed?.message ? { code: 'PARTIAL_EXIT', message: failed.message } : {}),
      });
    }
    return results.find(result => result?.code === 'SUBREQUEST_LIMIT' || result?.code === 'PROBE_BUDGET_EXHAUSTED')
      ?? results.find(result => result?.status === 'unknown') ?? failed ?? unknown(target, 'CANCELLED', '检测已取消');
  }

  // 后端批量共用四个 TCP 配额，留出 KV / 备用 HTTP 连接；排队不消耗候选超时。
  private async limited(task: () => Promise<ProbeResult>, signal?: AbortSignal): Promise<ProbeResult | undefined> {
    if (signal?.aborted) return undefined;
    if (this.active >= 4) {
      const acquired = await new Promise<boolean>(resolve => {
        const wake = () => { signal?.removeEventListener('abort', cancel); resolve(true); };
        const cancel = () => { this.waiting = this.waiting.filter(item => item !== wake); resolve(false); };
        this.waiting.push(wake); signal?.addEventListener('abort', cancel, { once: true });
      });
      if (!acquired) return undefined;
    } else this.active++;
    try { return signal?.aborted ? undefined : await task(); }
    finally { const next = this.waiting.shift(); if (next) next(); else this.active--; }
  }

  private async checkExit(target: ProxyTarget, url: URL, connect: ProbeConnect, context: ProbeContext): Promise<ProbeResult> {
    const timeout = createRequestTimeout(this.options.timeoutMs, context.signal);
    const started = Date.now();
    let socket: ProbeSocket | undefined;
    let phase = 'PROBE_API_ERROR';
    const details = () => ({ endpoint: this.name, latencyMs: Date.now() - started });
    let abort: () => void = () => {};
    const cancelled = new Promise<never>((_, reject) => {
      abort = () => { void socket?.close().catch(() => {}); reject(new Error('cancelled')); };
      timeout.signal.addEventListener('abort', abort, { once: true });
    });
    try {
      return await Promise.race([cancelled, (async () => {
        phase = 'TARGET_CONNECT_ERROR';
        socket = await connect({ hostname: target.family === 'ipv6' ? `[${target.host}]` : target.host, port: target.port }, { secureTransport: 'off', allowHalfOpen: false });
        void socket.closed.catch(() => {});
        if (timeout.signal.aborted) { void socket.close().catch(() => {}); throw new Error('cancelled'); }
        await socket.opened;
        if (timeout.signal.aborted) throw new Error('cancelled');
        phase = this.options.secure ? 'TARGET_TLS_ERROR' : 'PROBE_API_ERROR';
        socket = await (this.options.secure ? this.options.secure(socket, url.hostname)
          : secureProbeSocket(socket, url.hostname, undefined, () => { phase = 'TARGET_TLS_ERROR'; }, this.options.rootsFetch));
        void socket.closed.catch(() => {});
        await socket.opened;
        if (timeout.signal.aborted) throw new Error('cancelled');
        phase = 'TARGET_HTTP_ERROR';
        const writer = socket.writable.getWriter();
        try { await writer.write(new TextEncoder().encode(`GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nAccept: application/json, text/plain, */*\r\nAccept-Language: en-US,en;q=0.9\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n`)); }
        finally { writer.releaseLock(); }
        const payload = await readHttpJson(socket.readable);
        const ip = payload.ip ?? payload.ipAddress;
        const address = typeof ip === 'string' ? parseProxyTarget(ip) : null;
        if (!address || address.family === 'hostname' || !/^[\da-f:.]+$/i.test(String(ip))
          || (address.family === 'ipv4' && address.host !== ip)) throw new Error('候选响应缺少有效出口 IP');
        const exit = readProbeExit(payload, undefined)!;
        const trusted: ProbeExit = { ...exit, ip: address.host, family: address.family };
        const colo = readText(payload.colo)?.toUpperCase();
        return alive(target, { ...details(), exits: [trusted], exitIp: address.host, exitFamily: address.family,
          ...(colo && /^[A-Z]{3}$/.test(colo) ? { colo } : {}),
        });
      })()]);
    } catch (error) {
      if (context.signal?.aborted) return unknown(target, 'CANCELLED', '检测已取消', details());
      if (error instanceof FetchBudgetError) return unknown(target, 'PROBE_BUDGET_EXHAUSTED', error.message, details());
      const message = typeof error === 'string' ? error : probeErrorMessage(error);
      if (isSubrequestLimit(message)) return unknown(target, 'SUBREQUEST_LIMIT', 'Worker 子请求额度已用尽', details());
      if (isTcpLoop(message)) return unknown(target, 'PROBE_API_ERROR', 'TCP Loop detected：运行平台拒绝回环连接', details());
      if (timeout.didTimeout()) return phase === 'PROBE_API_ERROR'
        ? unknown(target, 'PROBE_API_ERROR', 'TLS 信任库准备超时，候选状态未知', details())
        : dead(target, { ...details(), code: 'TIMEOUT', message: '候选连接超时' });
      if (phase === 'PROBE_API_ERROR' || error instanceof TypeError) return unknown(target, 'PROBE_API_ERROR', '原生检测运行异常', details());
      const stage = phase === 'TARGET_CONNECT_ERROR' ? '候选 TCP 连接失败'
        : phase === 'TARGET_TLS_ERROR' ? '候选 TLS 验证失败' : '候选 HTTP 或出口 JSON 无效';
      return dead(target, { ...details(), code: phase, message: stage + '：' + this.redact(message).slice(0, 180) });
    } finally {
      timeout.signal.removeEventListener('abort', abort); timeout.cleanup();
      await socket?.close().catch(() => {});
    }
  }
}

/** 有界 HTTP/1.1 JSON 响应；定长或分块正文收齐后即停止读取。 */
async function readHttpJson(stream: ReadableStream<Uint8Array>): Promise<Record<string, unknown>> {
  const decoder = new TextDecoder();
  let bytes = new Uint8Array(1024), size = 0, headerEnd = -1;
  let chunked = false, declared: number | undefined;
  const chunks: Uint8Array[] = [];
  let chunkStart = 0, chunkBytes = 0, complete = false;
  const reader = stream.getReader();
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      const end = size + chunk.value.length;
      if (end > READ_LIMIT) throw new Error('候选响应超过 64 KiB');
      if (end > bytes.length) {
        const grown = new Uint8Array(Math.max(end, bytes.length * 2));
        grown.set(bytes); bytes = grown;
      }
      bytes.set(chunk.value, size);
      if (headerEnd < 0) {
        headerEnd = findCrlf(bytes.subarray(0, end), Math.max(0, size - 3), true);
        if (headerEnd >= 0) {
          const headers = decoder.decode(bytes.subarray(0, headerEnd));
          const status = /^HTTP\/1\.[01] (\d{3})\b/.exec(headers)?.[1];
          if (status !== '200') throw new Error('HTTP ' + (status ?? '响应格式无效'));
          if (/\r\ncontent-encoding:\s*(?!identity\s*(?:\r|$))\S/i.test(headers)) throw new Error('encoded response');
          const transfer = headers.match(/\r\ntransfer-encoding:[ \t]*([^\r\n]+)/i)?.[1]?.trim().toLowerCase();
          if (transfer && transfer !== 'chunked') throw new Error('unsupported transfer encoding');
          chunked = transfer === 'chunked';
          chunkStart = headerEnd + 4;
          const lengths = [...headers.matchAll(/\r\ncontent-length:[ \t]*([^\r\n]*)/gi)];
          if (!chunked && lengths.length) {
            const length = lengths[0]![1]!.trim();
            if (lengths.length !== 1 || !/^\d+$/.test(length)) throw new Error('invalid content length');
            declared = Number(length);
            if (headerEnd + 4 + declared > READ_LIMIT) throw new Error('候选响应超过 64 KiB');
          }
        }
      }
      size = end;
      if (declared !== undefined && size >= headerEnd + 4 + declared) break;
      if (!chunked) continue;
      const received = bytes.subarray(0, size);
      while (chunkStart < size) {
        const header = findCrlf(received, chunkStart);
        if (header < 0) break;
        const hex = decoder.decode(bytes.subarray(chunkStart, header)).split(';')[0]!;
        if (!/^[\da-f]+$/i.test(hex)) throw new Error('invalid chunk size');
        const count = Number.parseInt(hex, 16);
        if (count > READ_LIMIT) throw new Error('invalid chunk size');
        const data = header + 2;
        if (!count) {
          complete = (bytes[data] === 13 && bytes[data + 1] === 10 && data + 2 <= size)
            || findCrlf(received, data, true) >= 0;
          break;
        }
        const next = data + count;
        if (next + 2 > size) break;
        if (bytes[next] !== 13 || bytes[next + 1] !== 10) throw new Error('invalid chunk ending');
        chunks.push(bytes.subarray(data, next)); chunkBytes += count; chunkStart = next + 2;
      }
      if (complete) break;
    }
  } finally { reader.releaseLock(); }
  if (headerEnd < 0) throw new Error(size ? '候选返回的 HTTP 响应不完整' : '候选未返回 HTTP 数据');
  let body = bytes.subarray(headerEnd + 4, size);
  if (chunked) {
    if (!complete) throw new Error('truncated chunked body');
    body = new Uint8Array(chunkBytes);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  } else if (declared !== undefined && declared !== body.length) throw new Error('invalid body length');
  const record = asRecord(JSON.parse(decoder.decode(body)));
  if (!record) throw new Error('invalid exit JSON');
  return record;
}
function findCrlf(bytes: Uint8Array, start: number, double = false): number {
  for (let i = start; i + (double ? 3 : 1) < bytes.length; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 10 && (!double || (bytes[i + 2] === 13 && bytes[i + 3] === 10))) return i;
  }
  return -1;
}
