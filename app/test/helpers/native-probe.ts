import { NativeProbeAdapter } from '../../src/adapters/probe/native';
import type { ProbeAdapter } from '../../src/ports/probe';
import { dispatchWorkerInvocation, type InvocationProps, type InvocationRequestInit } from '../../src/worker';
import type { RuntimeEnv } from '../../src/config/runtime';

/** 在真实适配器的候选连接阶段失败，不访问任何网络。 */
export function failingNativeProbe(error: Error, backup?: ProbeAdapter): NativeProbeAdapter {
  return new NativeProbeAdapter({
    urls: ['https://exit.example.test/'], timeoutMs: 1000, ...(backup ? { backup } : {}),
    connect: () => ({
      opened: Promise.reject(error), closed: Promise.resolve(),
      readable: new ReadableStream(), writable: new WritableStream(),
      close: async () => {}, startTls: () => { throw new Error('unexpected TLS attempt'); },
    }),
  });
}

/** 本地宿主模拟 workerd 的默认内部绑定；所有调用仍进入真实 Worker。 */
export function localWorkerContext(worker: ExportedHandler<RuntimeEnv>, env: RuntimeEnv,
  waitUntil: (task: Promise<unknown>) => void = () => undefined): ExecutionContext {
  const context = { waitUntil, passThroughOnException() {}, props: {},
    exports: { default: { dispatch: (url: string, init: InvocationRequestInit, props: InvocationProps, cancelled: ReadableStream<Uint8Array>) =>
      dispatchWorkerInvocation(worker, env, context, url, init, props, cancelled) } },
  } as unknown as ExecutionContext;
  return context;
}
