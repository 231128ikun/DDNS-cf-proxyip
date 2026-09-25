import type { HealthResponse } from '../../../src/contracts/probe';
import type { RequestState } from '../state/request-state';
import { Icon } from './icon';

interface HeroProps {
  readonly health: RequestState<HealthResponse>;
  readonly usageOpen: boolean;
  readonly onToggleUsage: () => void;
  readonly onOpenConfig: () => void;
}

export function Hero({ health, usageOpen, onToggleUsage, onOpenConfig }: HeroProps) {
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
            <span class="target-summary-domain">维护域名与 Cloudflare 权限</span>
            <span class="target-summary-meta">前往配置中心添加或调整</span>
          </span>
        </button>
      </div>
    </div>
  );
}
