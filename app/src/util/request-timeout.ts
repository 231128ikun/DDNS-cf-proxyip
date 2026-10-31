/**
 * 统一的外部请求超时：本地定时器负责超时，调用方的 signal 负责取消。
 * 维护、探针和 DNS 查询共用这一份实现，避免各处再写一套计时与清理。
 */
export interface RequestTimeout {
  readonly signal: AbortSignal;
  /** 只有本地定时器触发、且调用方没有主动取消时才是超时。 */
  readonly didTimeout: () => boolean;
  readonly cleanup: () => void;
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
