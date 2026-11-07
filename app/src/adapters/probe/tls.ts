import { LazyReadFunctionReadQueue, startTls, TrustedCert, type RootCertsDatabase } from 'subtls';
import { appFetch, FetchBudgetError } from '../../util/fetch';
import { createRequestTimeout } from '../../util/request-timeout';
import type { ProbeSocket } from './native';

let roots: { expires: number; value: RootCertsDatabase } | undefined;
const loads = new WeakMap<typeof fetch, Promise<RootCertsDatabase>>();

/** 只跨请求复用已读取的数据；进行中的 I/O 和失败结果只在本次调用共享。 */
async function trustRoots(fetchRoots: typeof fetch): Promise<RootCertsDatabase> {
  if (roots && roots.expires >= Date.now()) return roots.value;
  if (!loads.has(fetchRoots)) {
    const value = (async () => {
      const timeout = createRequestTimeout(5000);
      try {
        const response = await fetchRoots('https://curl.se/ca/cacert.pem', { signal: timeout.signal });
        if (!response.ok) {
          await response.body?.cancel().catch(() => {});
          throw new Error('CA HTTP ' + response.status);
        }
        const pem = await response.text();
        if (pem.length > 400_000 || !pem.includes('-----BEGIN CERTIFICATE-----')) throw new Error('invalid CA bundle');
        const value = await TrustedCert.databaseFromPEM(pem);
        roots = { expires: Date.now() + 86_400_000, value };
        return value;
      } finally { timeout.cleanup(); }
    })();
    loads.set(fetchRoots, value);
  }
  try { return await loads.get(fetchRoots)!; }
  catch (error) {
    if (error instanceof FetchBudgetError) throw error;
    throw new TypeError('TLS 信任库加载失败，候选状态未知');
  }
}

/** 显式发送 SNI 并验证证书链，绕开生产边缘 startTls 的 SNI 丢失问题。 */
export async function secureProbeSocket(socket: ProbeSocket, hostname: string,
  certificates?: RootCertsDatabase, onHandshake?: () => void, fetchRoots: typeof fetch = appFetch): Promise<ProbeSocket> {
  const trusted = certificates ?? await trustRoots(fetchRoots);
  onHandshake?.();
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let pending = Promise.resolve();
  const queue = new LazyReadFunctionReadQueue(async () => {
    await pending;
    const chunk = await reader.read();
    return chunk.done ? undefined : chunk.value;
  });
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => closing ??= (async () => {
    await socket.close().catch(() => {});
    await reader.cancel().catch(() => {});
    reader.releaseLock(); writer.releaseLock();
  })();
  try {
    const tls = await startTls(hostname, trusted, queue.read.bind(queue), data => {
      pending = pending.then(() => writer.write(data));
      void pending.catch(() => {});
    }, { useSNI: true, requireServerTlsExtKeyUsage: true, requireDigitalSigKeyUsage: true });
    await pending;
    return {
      opened: socket.opened, closed: socket.closed, close,
      readable: new ReadableStream({
        async pull(controller) {
          try { const bytes = await tls.read(); if (bytes?.length) controller.enqueue(bytes); else controller.close(); }
          catch (error) { controller.error(error); }
        }, cancel: close,
      }),
      writable: new WritableStream({ async write(data) { await tls.write(data); await pending; }, abort: close }),
      startTls() { throw new Error('TLS 已建立'); },
    };
  } catch (error) { await close(); throw error; }
}
