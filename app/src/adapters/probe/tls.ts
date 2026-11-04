import { LazyReadFunctionReadQueue, startTls, TrustedCert, type RootCertsDatabase } from 'subtls';
import { appFetch } from '../../util/fetch';
import { createRequestTimeout } from '../../util/request-timeout';
import type { ProbeSocket } from './native';

let roots: { expires: number; value: Promise<RootCertsDatabase> } | undefined;

/** CA 数据只缓存于当前 isolate，不写 KV；失败不缓存，不能据此判候选失效。 */
async function trustRoots(): Promise<RootCertsDatabase> {
  if (!roots || roots.expires < Date.now()) {
    const value = (async () => {
      const timeout = createRequestTimeout(5000);
      try {
        const response = await appFetch('https://curl.se/ca/cacert.pem', { signal: timeout.signal });
        if (!response.ok) throw new Error('CA HTTP ' + response.status);
        const pem = await response.text();
        if (pem.length > 400_000 || !pem.includes('-----BEGIN CERTIFICATE-----')) throw new Error('invalid CA bundle');
        return await TrustedCert.databaseFromPEM(pem);
      } finally { timeout.cleanup(); }
    })();
    roots = { expires: Date.now() + 86_400_000, value };
    void value.catch(() => { if (roots?.value === value) roots = undefined; });
  }
  try { return await roots.value; }
  catch { throw new TypeError('TLS 信任库加载失败，候选状态未知'); }
}

/** 显式发送 SNI 并验证证书链，绕开生产边缘 startTls 的 SNI 丢失问题。 */
export async function secureProbeSocket(socket: ProbeSocket, hostname: string,
  certificates?: RootCertsDatabase, onHandshake?: () => void): Promise<ProbeSocket> {
  const trusted = certificates ?? await trustRoots();
  onHandshake?.();
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let pending = Promise.resolve();
  const queue = new LazyReadFunctionReadQueue(async () => {
    await pending;
    const chunk = await reader.read();
    return chunk.done ? undefined : chunk.value;
  });
  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    await socket.close().catch(() => {});
    await reader.cancel().catch(() => {});
    reader.releaseLock(); writer.releaseLock();
  };
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
