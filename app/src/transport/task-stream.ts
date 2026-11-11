import { JSON_STREAM_TYPE } from '../contracts/json-stream';

/** 检测和维护共用流式结果、取消及任务存活处理。 */
export function streamTask<Result>(run: (send: (event: object) => void, signal: AbortSignal) => Promise<Result>,
  requestSignal: AbortSignal, failureMessage: string, waitUntil?: (task: Promise<unknown>) => void): Response {
  const encoder = new TextEncoder();
  const abort = new AbortController();
  const stop = () => abort.abort();
  if (requestSignal.aborted) stop();
  else requestSignal.addEventListener('abort', stop, { once: true });
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      const send = (event: object) => {
        if (cancelled) return;
        try { controller.enqueue(encoder.encode(JSON.stringify(event) + '\n')); }
        catch { cancelled = true; stop(); }
      };
      const task = Promise.resolve().then(() => { abort.signal.throwIfAborted(); return run(send, abort.signal); })
        .then(result => send({ type: 'result', result }))
        .catch((error: unknown) => {
          if (abort.signal.aborted) console.error('任务已取消');
          else console.error(failureMessage, error instanceof Error ? error.name : 'UnknownError');
          send({ type: 'error', message: failureMessage });
        }).finally(() => {
          requestSignal.removeEventListener('abort', stop);
          if (!cancelled) controller.close();
        });
      waitUntil?.(task);
    },
    cancel() { cancelled = true; stop(); },
  });
  return new Response(body, { headers: { 'Content-Type': JSON_STREAM_TYPE, 'Cache-Control': 'no-store, no-transform' } });
}
