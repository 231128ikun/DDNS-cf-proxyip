import type { RequestState } from '../state/request-state';

interface ResourceFeedbackProps {
  readonly state: RequestState<unknown>;
  readonly id: string;
  readonly onRetry: () => void;
}

/** 读取失败可单独重试；已确认的数据继续展示。 */
export function ResourceFeedback({ state, id, onRetry }: ResourceFeedbackProps) {
  const message = state.status === 'error' ? state.message : state.status === 'ready' ? state.refreshError : null;
  if (!message) return null;
  return (
    <div class="kv-alert compact" role="alert">
      <p class="mb-2">{state.status === 'ready' ? `刷新失败：${message}。已保留上次确认的数据。` : message}</p>
      <button id={id} class="btn btn-sm btn-outline-primary" type="button" onClick={onRetry}>重试读取</button>
    </div>
  );
}
