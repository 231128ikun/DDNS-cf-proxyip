import type { ConfigResponse } from '../../../src/contracts/config';
import type { HealthResponse } from '../../../src/contracts/probe';
import type { RequestState } from '../state/request-state';
import { Icon } from './icon';

export type GlobalSettingKey = 'scheduledEnabled' | 'tgEnabled';

interface HeroProps {
  readonly health: RequestState<HealthResponse>;
  readonly config: RequestState<ConfigResponse>;
  readonly saving: boolean;
  readonly usageOpen: boolean;
  readonly onToggleUsage: () => void;
  readonly onToggleSetting: (key: GlobalSettingKey, enabled: boolean) => void;
}

export function Hero({ health, config, saving, usageOpen, onToggleUsage, onToggleSetting }: HeroProps) {
  return (
    <div class="container hero">
      <div class="hero-copy">
        <h1><Icon name="globe" /> DDNS Pro 多域名管理</h1>
        <div class="hero-actions">
          <button type="button" class="guide-toggle" onClick={onToggleUsage} aria-expanded={usageOpen} aria-controls="usage-guide" aria-label={usageOpen ? '收起使用说明' : '使用说明'}><Icon name="help" /></button>
          <div class="config-info"><span><Icon name="compass" /> 建议流程：导入IP → 检测 → 入库 → 执行维护</span></div>
        </div>
      </div>
      <fieldset class="header-settings" aria-label="全局任务设置" aria-busy={saving} disabled={saving || config.status !== 'ready'}>
        {config.status === 'ready' ? ([['scheduledEnabled', '自动维护', 'cfg-scheduled-enabled'], ['tgEnabled', 'Telegram 通知', 'cfg-tg-enabled']] as const).map(([key, label, id]) => (
          <label class="setting-switch" key={key}>
            <input id={id} type="checkbox" role="switch" checked={config.data.config[key]} onChange={(event) => onToggleSetting(key, event.currentTarget.checked)} />
            <span class="setting-switch-track" aria-hidden="true" /><span>{label}</span>
          </label>
        )) : <span class="text-secondary small">{config.status === 'error' ? '配置读取失败' : '正在读取配置…'}</span>}
      </fieldset>
      {health.status === 'error' && <div class="kv-alert"><strong>Worker API 暂不可用。</strong>{health.message}。页面仍可浏览，但检测和后续维护功能不可用。</div>}
      <div id="usage-guide" class="usage-guide" hidden={!usageOpen}>
        <ol>
          <li><strong>准备IP</strong>：在左侧 <code>IP库管理</code> 中手动输入或远程加载 IP，点击【检测】筛出可用 IP。</li>
          <li><strong>保存到池</strong>：选择上方的 IP 池（默认为默认池），点击【入库】将可用 IP 入库。</li>
          <li><strong>执行维护</strong>：在解析实况选择要维护的域名，点击右侧【执行全部维护】或依靠定时任务自动维护。</li>
        </ol>
      </div>
    </div>
  );
}
