import { NativeProbeAdapter } from '../../src/adapters/probe/native';
import type { ProbeAdapter } from '../../src/ports/probe';

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
