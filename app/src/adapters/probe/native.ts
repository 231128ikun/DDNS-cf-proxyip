import { asRecord } from '../../contracts/parse';
import { alive, dead, unknown, type ProbeExit, type ProbeResult } from '../../domain/probe-result';
import { parseProxyTarget, type ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../../ports/probe';
import { createRequestTimeout } from '../../util/request-timeout';
import { readProbeExit, readText, uniqueExits } from './probe-payload';
import { isTcpLoop } from './probe-errors';
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
}
const READ_LIMIT = 65_536;

/** 候选 TCP + 显式 SNI/Host；两个出口分支复用同一 TLS 适配器。 */
export class NativeProbeAdapter implements ProbeAdapter {
  readonly name = 'native';
  private active = 0;
  private waiting: (() => void)[] = [];
  private readonly redact: (message: string) => string;
  constructor(private readonly options: NativeProbeOptions) {
    this.redact = createProbeRedactor(options.urls.map(urlTemplate => ({ name: 'native', urlTemplate })));
  }

  async probe(target: ProxyTarget, context: ProbeContext = {}): Promise<ProbeResult> {
    const first = await this.check(target, context);
    if (first.status === 'alive' || context.signal?.aborted) return first;
    const second = this.options.backup
      ? await this.limited(() => this.options.backup!.probe(target, context), context.signal)
        ?? unknown(target, 'CANCELLED', '检测已取消')
      : await this.check(target, context);
    // 任一轮自身异常都不能凭另一轮的失败推断节点失效；明确成功可以恢复。
    if (second.status === 'alive') return second;
    return first.status === 'unknown' && second.status === 'dead' ? first : second;
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
    const results = await Promise.all(urls.map(url => this.limited(() => this.checkExit(target, url, connect!, context), context.signal)));
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
    return results.find(result => result?.status === 'unknown') ?? failed ?? unknown(target, 'CANCELLED', '检测已取消');
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
          : secureProbeSocket(socket, url.hostname, undefined, () => { phase = 'TARGET_TLS_ERROR'; }));
        void socket.closed.catch(() => {});
        await socket.opened;
        if (timeout.signal.aborted) throw new Error('cancelled');
        phase = 'TARGET_HTTP_ERROR';
        const writer = socket.writable.getWriter();
        try { await writer.write(new TextEncoder().encode(`GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nAccept: application/json, text/plain, */*\r\nAccept-Language: en-US,en;q=0.9\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n`)); }
        finally { writer.releaseLock(); }
        const reader = socket.readable.getReader();
        const chunks: Uint8Array[] = [];
        let size = 0;
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.length;
            if (size > READ_LIMIT) throw new Error('候选响应超过 64 KiB');
            chunks.push(chunk.value);
          }
        } finally { reader.releaseLock(); }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        const payload = readHttpJson(bytes);
        const ip = payload.ip ?? payload.ipAddress;
        const address = typeof ip === 'string' ? parseProxyTarget(ip) : null;
        if (!address || address.family === 'hostname' || address.host !== String(ip).toLowerCase()) throw new Error('候选响应缺少有效出口 IP');
        const exit = readProbeExit(payload, undefined)!;
        const trusted: ProbeExit = { ...exit, ip: address.host, family: address.family };
        const colo = readText(payload.colo)?.toUpperCase();
        return alive(target, { ...details(), exits: [trusted], exitIp: address.host, exitFamily: address.family,
          ...(colo && /^[A-Z]{3}$/.test(colo) ? { colo } : {}),
        });
      })()]);
    } catch (error) {
      if (context.signal?.aborted) return unknown(target, 'CANCELLED', '检测已取消', details());
      if (isTcpLoop(error instanceof Error ? error.message : String(error))) return unknown(target, 'PROBE_API_ERROR', 'TCP Loop detected：运行平台拒绝回环连接', details());
      if (timeout.didTimeout()) return phase === 'PROBE_API_ERROR'
        ? unknown(target, 'PROBE_API_ERROR', 'TLS 信任库准备超时，候选状态未知', details())
        : dead(target, { ...details(), code: 'TIMEOUT', message: '候选连接超时' });
      if (phase === 'PROBE_API_ERROR' || error instanceof TypeError) return unknown(target, 'PROBE_API_ERROR', '原生检测运行异常', details());
      const stage = phase === 'TARGET_CONNECT_ERROR' ? '候选 TCP 连接失败'
        : phase === 'TARGET_TLS_ERROR' ? '候选 TLS 验证失败' : '候选 HTTP 或出口 JSON 无效';
      return dead(target, { ...details(), code: phase, message: stage + '：' + this.redact(probeErrorMessage(error)).slice(0, 180) });
    } finally {
      timeout.signal.removeEventListener('abort', abort); timeout.cleanup();
      void socket?.close().catch(() => {});
    }
  }
}

/** 有界 HTTP/1.1 JSON 响应；分块长度按字节处理，不能按 JS 字符串截断。 */
function readHttpJson(bytes: Uint8Array): Record<string, unknown> {
  const decoder = new TextDecoder();
  const headerEnd = findCrlf(bytes, 0, true);
  if (headerEnd < 0) throw new Error(bytes.length ? '候选返回的 HTTP 响应不完整' : '候选未返回 HTTP 数据');
  const headers = decoder.decode(bytes.subarray(0, headerEnd));
  const status = /^HTTP\/1\.[01] (\d{3})\b/.exec(headers)?.[1];
  if (status !== '200') throw new Error('HTTP ' + (status ?? '响应格式无效'));
  if (/\r\ncontent-encoding:\s*(?!identity\s*(?:\r|$))\S/i.test(headers)) throw new Error('encoded response');
  let body = bytes.subarray(headerEnd + 4);
  if (/\r\ntransfer-encoding:\s*chunked\s*(?:\r|$)/i.test(headers)) {
    const chunks: Uint8Array[] = [];
    let length = 0, pos = 0;
    while (true) {
      const end = findCrlf(body, pos);
      if (end < 0) throw new Error('truncated chunk header');
      const hex = decoder.decode(body.subarray(pos, end)).split(';')[0]!;
      if (!/^[\da-f]+$/i.test(hex)) throw new Error('invalid chunk size');
      const count = Number.parseInt(hex, 16);
      if (!Number.isSafeInteger(count) || count > READ_LIMIT) throw new Error('invalid chunk size');
      pos = end + 2;
      if (!count) break;
      if (pos + count + 2 > body.length || body[pos + count] !== 13 || body[pos + count + 1] !== 10) throw new Error('truncated chunk');
      chunks.push(body.subarray(pos, pos + count)); length += count; pos += count + 2;
    }
    body = new Uint8Array(length); pos = 0;
    for (const chunk of chunks) { body.set(chunk, pos); pos += chunk.length; }
  } else {
    const declared = headers.match(/\r\ncontent-length:\s*(\d+)/i)?.[1];
    if (declared && Number(declared) !== body.length) throw new Error('truncated body');
  }
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
