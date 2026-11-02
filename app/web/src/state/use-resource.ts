import { useCallback, useRef, useState } from 'preact/hooks';
import { errorMessage, isAbort, isUnavailable } from '../api/errors';
import type { RequestState } from './request-state';

/**
 * 接受写入响应后，旧读取不能覆盖已确认数据。
 * refresh 身份保持稳定，避免重渲染重复触发首屏预取。
 */
export function useResource<T extends object>(
  load: (signal?: AbortSignal, progress?: (data: T) => void) => Promise<T>,
  retainData = false,
  initialData?: T,
): readonly [
  RequestState<T>,
  (signal?: AbortSignal) => Promise<boolean>,
  (value: T | ((current: T) => T)) => void,
] {
  const latest = useRef(load);
  latest.current = load;
  const [state, setState] = useState<RequestState<T>>(initialData ? { status: 'ready', data: initialData } : { status: 'loading' });
  const latestRequest = useRef(0);
  const cached = useRef<T | null>(initialData ?? null);

  const refresh = useCallback(async (signal?: AbortSignal): Promise<boolean> => {
    const request = ++latestRequest.current;
    setState(retainData && cached.current
      ? { status: 'ready', data: cached.current, refreshing: true }
      : { status: 'loading' });
    try {
      const data = await latest.current(signal, (data) => {
        if (signal?.aborted || request !== latestRequest.current) return;
        cached.current = data;
        setState({ status: 'ready', data, refreshing: true });
      });
      if (signal?.aborted || request !== latestRequest.current) return false;
      cached.current = data;
      setState({ status: 'ready', data });
      return true;
    } catch (error) {
      if (isAbort(error) || signal?.aborted || request !== latestRequest.current) return false;
      setState(retainData && cached.current ? {
        status: 'ready', data: cached.current, refreshError: errorMessage(error),
      } : {
        status: 'error',
        message: errorMessage(error),
        unavailable: isUnavailable(error),
      });
      return false;
    } finally {
      if (signal?.aborted && request === latestRequest.current && retainData && cached.current) {
        setState({ status: 'ready', data: cached.current });
      }
    }
  }, [retainData]);

  const update = useCallback((value: T | ((current: T) => T)): void => {
    if (typeof value === 'function' && !cached.current) return;
    const data = typeof value === 'function' ? (value as (current: T) => T)(cached.current!) : value;
    latestRequest.current++;
    cached.current = data;
    // 局部写入只确认修改的条目，不能把整份列表此前的回读失败当作已恢复。
    setState(current => ({ status: 'ready', data,
      ...(typeof value === 'function' && current.status === 'ready' && current.refreshError
        ? { refreshError: current.refreshError } : {}),
    }));
  }, []);

  return [state, refresh, update];
}
