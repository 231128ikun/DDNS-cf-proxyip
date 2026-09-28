import { useCallback, useRef, useState } from 'preact/hooks';
import { errorMessage, isAbort } from '../api/errors';
import type { RequestState } from './request-state';

/**
 * 面板上的只读资源都是同一种形状：拉一次、成功给数据、失败给文案、还能重试。
 * 这里只实现一次，页面只保留刷新入口和“就地改一份”的乐观更新入口。
 * refresh 的身份保持稳定，因此首屏的并行预取不会因为重渲染而重复触发。
 */
export function useResource<T>(
  load: (signal?: AbortSignal) => Promise<T>,
): readonly [
  RequestState<T>,
  (signal?: AbortSignal) => Promise<void>,
  (mutate: (current: T) => T) => void,
] {
  const latest = useRef(load);
  latest.current = load;
  const [state, setState] = useState<RequestState<T>>({ status: 'loading' });

  const refresh = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setState({ status: 'loading' });
    try {
      setState({ status: 'ready', data: await latest.current(signal) });
    } catch (error) {
      if (isAbort(error)) return;
      setState({ status: 'error', message: errorMessage(error) });
    }
  }, []);

  const mutate = useCallback((change: (current: T) => T): void => {
    setState((current) => (current.status === 'ready' ? { status: 'ready', data: change(current.data) } : current));
  }, []);

  return [state, refresh, mutate];
}
