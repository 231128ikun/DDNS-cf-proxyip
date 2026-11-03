import type { DomainBindingItem, DomainBindingsResponse } from '../../../src/contracts/maintenance';
import type { RequestState } from '../state/request-state';
import { RecordBadge } from './record-badge';

export interface TargetSelectorProps {
  readonly bindings: RequestState<DomainBindingsResponse>;
  readonly selectedTargetKey: string | null;
  readonly targetPort: number | 'any';
  readonly targetChoices: readonly Pick<DomainBindingItem, 'key' | 'domain' | 'mode'>[];
  readonly onSelectTarget: (key: string | null) => void;
}

export function TargetSelector({ bindings, selectedTargetKey, targetPort, targetChoices, onSelectTarget }: TargetSelectorProps) {
  return (
      <div class="domain-selector">
        <label class="target-summary">
          <span id="current-target-summary-content">
            <TargetSummary state={bindings} selectedKey={selectedTargetKey} port={targetPort} targetChoices={targetChoices} />
          </span>
          <select
            class="target-select-overlay"
            aria-label="选择维护域名"
            value={selectedTargetKey ?? ''}
            onChange={(event) => onSelectTarget(event.currentTarget.value || null)}
          >
            {targetChoices.length > 0 ? (
              targetChoices.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.domain} - {item.mode === 'TXT' ? 'TXT' : 'A/AAAA'}
                </option>
              ))
            ) : (
              <option value="">未配置维护域名</option>
            )}
          </select>
        </label>
      </div>
  );
}

/**
 * 解析实况中的维护目标摘要。
 *
 * 目标来自已读取的配置时立即展示，不等待绑定的排序和池映射。
 * 没有目标可展示时，仍区分绑定未读完、读取失败和未初始化。
 */
function TargetSummary({
  state,
  selectedKey,
  port,
  targetChoices,
}: {
  readonly state: RequestState<DomainBindingsResponse>;
  readonly selectedKey: string | null;
  readonly port: number | 'any';
  readonly targetChoices: TargetSelectorProps['targetChoices'];
}) {
  const item = targetChoices.find((candidate) => candidate.key === selectedKey) ?? targetChoices[0];
  if (item) {
    return (
      <>
        <RecordBadge mode={item.mode} />
        <span class="target-summary-domain" title={item.domain}>{item.domain}</span>
        <span class="target-summary-meta">
          {item.mode === 'A' && port !== 'any' ? `端口 ${port}` : `${item.mode === 'TXT' ? 'TXT' : 'A/AAAA'} 记录`}
        </span>
      </>
    );
  }
  if (state.status === 'loading' || state.status === 'idle') {
    return (
      <>
        <span class="target-summary-domain">正在读取维护域名…</span>
        <span class="target-summary-meta">稍候即可</span>
      </>
    );
  }
  if (state.status === 'error') {
    // 503 是"存储还没绑定"，新部署第一次打开就是这种状态，按未初始化引导。
    if (state.unavailable) {
      return (
        <>
          <span class="target-summary-domain">尚未初始化</span>
          <span class="target-summary-meta">绑定 KV 后在配置中心保存配置即可开始</span>
        </>
      );
    }
    return (
      <>
        <span class="target-summary-domain">维护域名读取失败</span>
        <span class="target-summary-meta text-danger">{state.message}</span>
      </>
    );
  }

  return (
    <>
      <span class="target-summary-domain">未配置维护域名</span>
      <span class="target-summary-meta">请先到配置中心添加</span>
    </>
  );
}
