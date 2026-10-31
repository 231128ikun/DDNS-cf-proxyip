interface LoadingStateProps {
  readonly phase: 'checking' | 'loading-app';
}

/** 静态启动占位和运行时共用同一套样式；就绪后立即移除，不制造额外等待。 */
export function LoadingState({ phase }: LoadingStateProps) {
  return (
    <div id="auth-loading" class="loading-shell" data-phase={phase} role="status" aria-live="polite">
      <div class="loading-panel">
        <span class="loading-indicator" aria-hidden="true" />
        <h1 class="loading-title">DDNS Pro</h1>
        <p class="loading-message">{phase === 'checking' ? '正在验证访问权限…' : '正在加载管理面板…'}</p>
      </div>
    </div>
  );
}
