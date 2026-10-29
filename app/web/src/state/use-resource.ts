import { useCallback, useRef, useState } from 'preact/hooks';
import { errorMessage, isAbort, isUnavailable } from '../api/errors';
import type { RequestState } from './request-state';

/**
 * 面板上的只读资源都是同一种形状：拉一次、成功给数据、失败给文案、还能重试。
 * 可保留上次确认的数据，并接受写入响应；接受新数据后旧读取不能覆盖它。
 * refresh 的身份保持稳定，因此首屏的并行预取不会因为重渲染而重复触发。
 */
export function useResource<T extends object>(
  load: (signal?: AbortSignal, progress?: (data: T) => void) => Promise<T>,
  retainData = false,
): readonly [
  RequestState<T>,
  (signal?: AbortSignal) => Promise<boolean>,
  (value: T | ((current: T) => T)) => void,
] {
  const latest = useRef(load);
  latest.current = load;
  const [state, setState] = useState<RequestState<T>>({ status: 'loading' });
  const latestRequest = useRef(0);
  const cached = useRef<T | null>(null);

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
