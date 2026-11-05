export type AppPage = 'dashboard' | 'config';

interface TopNavProps {
  readonly page: AppPage;
  readonly onPageChange: (page: AppPage) => boolean;
}

export function TopNav({ page, onPageChange }: TopNavProps) {
  const pages = ['dashboard', 'config'] as const;
  return (
    <div class="top-nav" role="tablist" aria-label="页面切换" onKeyDown={event => {
      const next = event.key === 'Home' ? 'dashboard' : event.key === 'End' ? 'config'
        : event.key === 'ArrowLeft' || event.key === 'ArrowRight' ? pages[1 - pages.indexOf(page)] : undefined;
      if (!next) return;
      event.preventDefault();
      if (onPageChange(next)) document.getElementById(`tab-${next}`)?.focus();
    }}>
      {pages.map(key => (
        <button key={key} id={`tab-${key}`} class={`nav-tab${page === key ? ' active' : ''}`}
          data-page={key} type="button" role="tab" aria-selected={page === key} tabIndex={page === key ? 0 : -1}
          aria-controls={`page-${key}`} onClick={() => onPageChange(key)}>
          {key === 'dashboard' ? '运行面板' : '配置中心'}
        </button>
      ))}
    </div>
  );
}
