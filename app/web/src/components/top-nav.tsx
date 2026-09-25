import { Icon } from './icon';

export type AppPage = 'dashboard' | 'config';

interface TopNavProps {
  readonly page: AppPage;
  readonly onPageChange: (page: AppPage) => void;
}

export function TopNav({ page, onPageChange }: TopNavProps) {
  return (
    <div class="top-nav" role="tablist" aria-label="页面切换">
      <button
        id="tab-dashboard"
        class={`nav-tab${page === 'dashboard' ? ' active' : ''}`}
        data-page="dashboard"
        type="button"
        role="tab"
        aria-selected={page === 'dashboard'}
        aria-controls="page-dashboard"
        onClick={() => onPageChange('dashboard')}
      >
        <Icon name="dashboard" /> 运行面板
      </button>
      <button
        id="tab-config"
        class={`nav-tab${page === 'config' ? ' active' : ''}`}
        data-page="config"
        type="button"
        role="tab"
        aria-selected={page === 'config'}
        aria-controls="page-config"
        onClick={() => onPageChange('config')}
      >
        <Icon name="settings" /> 配置中心
      </button>
    </div>
  );
}
