/** 本地定时器负责超时，调用方的 signal 负责主动取消。 */
export interface RequestTimeout {
  readonly signal: AbortSignal;
  /** 只有本地定时器触发、且调用方没有主动取消时才是超时。 */
  readonly didTimeout: () => boolean;
  readonly cleanup: () => void;
}

/** 中止等待时仍接住底层操作的迟到结果或异常。 */
export function waitWithSignal<T>(task: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const stop = () => { signal.removeEventListener('abort', stop); reject(signal.reason); };
    signal.addEventListener('abort', stop, { once: true });
    if (signal.aborted) stop();
    task.then(value => { signal.removeEventListener('abort', stop); resolve(value); },
      error => { signal.removeEventListener('abort', stop); reject(error); });
  });
}

export function createRequestTimeout(timeoutMs: number, externalSignal?: AbortSignal): RequestTimeout {
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
    didTimeout: () => timedOut && !externalSignal?.aborted,
    cleanup: () => {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', handleExternalAbort);
    },
  };
}
