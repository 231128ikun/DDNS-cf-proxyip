import type { DomainBindingsResponse } from '../../../src/contracts/maintenance';
import type { HealthResponse } from '../../../src/contracts/probe';
import type { RequestState } from '../state/request-state';
import { Icon } from './icon';

interface HeroProps {
  readonly health: RequestState<HealthResponse>;
  readonly bindings: RequestState<DomainBindingsResponse>;
  readonly usageOpen: boolean;
  readonly onToggleUsage: () => void;
  readonly onOpenConfig: () => void;
}

export function Hero({ health, bindings, usageOpen, onToggleUsage, onOpenConfig }: HeroProps) {
  return (
    <div class="container hero">
      <h1><Icon name="globe" /> DDNS Pro 多域名管理</h1>
      <div class="hero-actions">
        <button
          type="button"
          class="guide-toggle"
          onClick={onToggleUsage}
          aria-expanded={usageOpen}
          title="使用步骤提示"
          aria-label="查看使用步骤"
        >
          <Icon name="help" />
        </button>
        <div class="config-info"><Icon name="settings" /> 建议流程：导入IP → 检测 → 入库 → 执行维护</div>
      </div>

      {health.status === 'error' && (
        <div class="kv-alert">
          <strong>Worker API 暂不可用。</strong>
          {health.message}。页面仍可浏览，但检测和后续维护功能不可用。
        </div>
      )}

      <div id="usage-guide" class="usage-guide" hidden={!usageOpen}>
        <ol>
          <li><strong>准备IP</strong>：在左侧 <code>IP库管理</code> 中手动输入或远程加载 IP，点击【检测】筛出可用 IP。</li>
          <li><strong>保存到池</strong>：选择上方的 IP 池（默认为默认池），点击【入库】将可用 IP 入库。</li>
          <li><strong>执行维护</strong>：在顶部选择要维护的域名，点击右侧【执行全部维护】或依靠定时任务自动维护。</li>
        </ol>
      </div>

      <div class="domain-selector">
        <button class="target-summary target-summary-button" type="button" onClick={onOpenConfig}>
          <span id="current-target-summary-content">
            <TargetSummary state={bindings} />
          </span>
        </button>
      </div>
    </div>
  );
}

/**
 * 顶部维护目标摘要。
 *
 * 这里只陈述"实际读到了什么"：绑定还没读完、接口失败、或一条都没配，
 * 都按各自的事实提示，绝不把"读不到"说成"权限没配"。
 */
function TargetSummary({ state }: { readonly state: RequestState<DomainBindingsResponse> }) {
  if (state.status === 'loading' || state.status === 'idle') {
    return (
      <>
        <span class="target-summary-domain">正在读取维护域名…</span>
        <span class="target-summary-meta">稍候即可</span>
      </>
    );
  }
  if (state.status === 'error') {
    return (
      <>
        <span class="target-summary-domain">维护域名读取失败</span>
        <span class="target-summary-meta text-danger">{state.message}</span>
      </>
    );
  }

  const item = state.data.items[0];
  if (!item) {
    return (
      <>
        <span class="target-summary-domain">未配置维护域名</span>
        <span class="target-summary-meta">点击前往配置中心添加</span>
      </>
    );
  }

  const extra = state.data.items.length - 1;
  return (
    <>
      <span class="target-summary-domain" title={item.domain}>{item.domain}</span>
      <span class="target-summary-meta">
        <span class={`record-badge ${item.mode === 'TXT' ? 'record-badge-txt' : 'record-badge-a'}`}>{item.mode}</span>
        <span>{item.mode === 'TXT' ? 'TXT 记录' : 'A/AAAA 记录'}</span>
        <span>{item.poolName}</span>
        {extra > 0 && <span>等 {state.data.items.length} 个目标</span>}
        {!item.enabled && <span class="text-warning">维护关闭</span>}
      </span>
    </>
  );
}