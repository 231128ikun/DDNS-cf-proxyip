import type { CleanPool } from '../application/clean-pool';
import { PoolInputError } from '../application/pool-service';
import type { CleanPoolEvent } from '../contracts/pool';

/** 保持一个请求，逐条回传进度；断开时取消尚未完成的检测。 */
export function cleanPoolStream(cleanPool: CleanPool, poolKey: string, requestSignal: AbortSignal): Response {
  const abort = new AbortController();
  const cancel = () => abort.abort();
  if (requestSignal.aborted) cancel();
  requestSignal.addEventListener('abort', cancel, { once: true });
  const encoder = new TextEncoder();
  let closed = false;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      const emit = (event: CleanPoolEvent) => { if (!closed) controller.enqueue(encoder.encode(JSON.stringify(event) + '\n')); };
      emit({ type: 'start' });
      void cleanPool.execute(poolKey, { signal: abort.signal }, ({ item, completed, total }) => {
        const { target: _target, ...result } = item.result;
        emit({ type: 'progress', completed, total, address: item.address, result });
      }).then(result => emit({ type: 'complete', result })).catch(error => {
        if (!abort.signal.aborted) {
          emit({ type: 'error', error: error instanceof PoolInputError ? error.message : '洗库未完成，请核对库存后重试' });
        }
      }).finally(() => {
        requestSignal.removeEventListener('abort', cancel);
        if (!closed) { closed = true; controller.close(); }
      });
    },
    cancel() { closed = true; cancel(); requestSignal.removeEventListener('abort', cancel); },
  });
  return new Response(body, { headers: { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store' } });
}
