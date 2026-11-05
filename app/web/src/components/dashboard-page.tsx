import { useLayoutEffect, useRef } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import type { PoolCheckResponse } from '../../../src/contracts/pool-check';
import type { CheckTargetResponse, HealthResponse } from '../../../src/contracts/probe';
import type { ConfigResponse } from '../../../src/contracts/config';
import type { RequestState } from '../state/request-state';
import type { TargetStatusView } from '../state/target-status';
import { Icon } from './icon';
import { StatusOverview } from './status-overview';
import type { TargetSelectorProps } from './target-selector';

/** 当前忙碌的池写操作。 */
export type PoolActionKey = 'pool-edit';
export type ConsoleTone = 'info' | 'success' | 'warning' | 'error';

export interface ConsoleLogEntry {
  readonly id: number;
  readonly time: string;
  readonly tone: ConsoleTone;
  readonly message: string;
}

export interface PoolCheckProgressState {
  readonly completed: number;
  readonly total: number;
}

export interface DashboardActions {
  readonly lookupSubmit: (event: Event) => void;
  readonly refresh: () => void;
  readonly addRecord: (value: string) => Promise<boolean>;
  readonly deleteRecord: (recordId: string, address?: string) => void;
  readonly runMaintenance: () => void;
}

interface DashboardPageProps extends Pick<TargetSelectorProps, 'bindings' | 'targetChoices' | 'onSelectTarget'> {
  readonly poolPanel: ComponentChildren;
  readonly config: RequestState<ConfigResponse>;
  readonly health: RequestState<HealthResponse>;
  readonly executionColos: readonly string[];
  readonly executionState: 'ready' | 'busy' | 'error';
  readonly check: RequestState<CheckTargetResponse>;
  readonly batch: RequestState<PoolCheckResponse>;
  readonly lookup: string;
  readonly consoleLogs: readonly ConsoleLogEntry[];
  readonly batchProgressState: PoolCheckProgressState | null;
  readonly targetStatus: RequestState<TargetStatusView>;
  readonly selectedTargetKey: string | null;
  readonly targetPort: number | 'any';
  readonly maintenanceBusy: boolean;
  readonly maintenanceBlocked: boolean;
  readonly actions: DashboardActions;
  readonly onCopyToInput: (address: string) => void;
  readonly onCopyAddress: (address: string) => void;
  readonly onLookupChange: (value: string) => void;
}


export function DashboardPage({
  poolPanel,
  config,
  health,
  executionColos,
  executionState,
  check,
  batch,
  lookup,
  consoleLogs,
  batchProgressState,
  targetStatus,
  bindings,
  targetChoices,
  onSelectTarget,
  selectedTargetKey,
  targetPort,
  maintenanceBusy,
  maintenanceBlocked,
  actions,
  onCopyToInput,
  onCopyAddress,
  onLookupChange,
}: DashboardPageProps) {

  return (
    <div id="page-dashboard" class="page-panel active" role="tabpanel" aria-labelledby="tab-dashboard">
      <StatusOverview
        check={check} current={targetStatus} selectedKey={selectedTargetKey} targetPort={targetPort}
        bindings={bindings} targetChoices={targetChoices} onSelectTarget={onSelectTarget}
        lookup={lookup} onLookupChange={onLookupChange} onLookup={actions.lookupSubmit}
        onRefresh={actions.refresh}
        onCopy={onCopyToInput} onCopyAddress={onCopyAddress} onAdd={actions.addRecord} onDelete={actions.deleteRecord}
      />


      <div class="dashboard-core-row">
          {poolPanel}

          <div class="card dashboard-card dashboard-console-card">
            <div class="dashboard-card-header">
              <h2 class="card-title m-0 fw-bold"><Icon name="dashboard" /> 控制台日志</h2>
              <span class="console-colo d-flex align-items-center gap-2" role="status" title={executionState === 'ready' ? '检测接口可用；节点失效不代表接口异常' : executionState === 'error' ? '检测请求异常' : '检测中或正在连接'}>
                <i class={`execution-dot ${executionState === 'ready' ? 'text-success' : executionState === 'error' ? 'text-danger' : 'text-secondary'}`} aria-hidden="true" />
                {executionColos.join(' / ') || (health.status === 'ready' ? health.data.executionColo ?? '未知' : health.status === 'error' ? '未知' : '连接中')}
              </span>
            </div>
            <Console logs={consoleLogs} config={config} />
              {batch.status !== 'idle' && <div
                class="progress console-progress mb-3"
                role="progressbar"
                aria-label="批量检测进度"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={batchProgress(batch, batchProgressState)}
                aria-valuetext={batch.status === 'ready' ? '检测完成' : batch.status === 'error' ? '检测已停止' : batchProgressLabel(batchProgressState)}
              >
                <div class="progress-bar console-progress-bar" style={{ width: `${batchProgress(batch, batchProgressState)}%` }} />
              </div>}
            <button
              class="btn btn-dark w-100"
              type="button"
              disabled={maintenanceBusy || maintenanceBlocked}
              onClick={actions.runMaintenance}
            >
              <Icon name="wrench" /> {maintenanceBusy ? '维护中…' : '执行全部维护'}
            </button>
          </div>
      </div>
    </div>
  );
}

function Console({ logs, config }: {
  readonly logs: readonly ConsoleLogEntry[];
  readonly config: RequestState<ConfigResponse>;
}) {
  const consoleRef = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  useLayoutEffect(() => {
    const element = consoleRef.current;
    if (element && follow.current) element.scrollTop = element.scrollHeight;
  }, [logs]);

  return (
    <div id="log-window" class="console mb-3" role="log" aria-label="控制台日志" aria-live="polite" aria-relevant="additions text" ref={consoleRef}
      onScroll={event => { const element = event.currentTarget; follow.current = element.scrollHeight - element.scrollTop - element.clientHeight < 32; }}>
      <div class="console-config" aria-label="配置详情">
        <div class="mb-2"><strong>运行配置</strong></div>
        {config.status === 'ready' && <div class="console-settings">
          <span>检测：内置探针{config.data.config.checkApiBackup ? ' + 备用接口' : ''}</span>
          <span>并发：{config.data.config.settings.CONCURRENT_CHECKS} · 超时：{config.data.config.settings.CHECK_TIMEOUT / 1000}s</span>
          <span>定时维护：{config.data.config.scheduledEnabled ? '开启' : '关闭'}</span>
          <span>Telegram：{config.data.config.tgEnabled ? '开启' : '关闭'}</span>
          <span>维护目标：{config.data.config.targets.filter(target => target.enabled).length} 个</span>
        </div>}
      </div>
      <div class="console-event-list">
        {logs.length === 0 && <div class="console-empty">正在连接系统…</div>}
        {logs.map(entry => {
          const tag = /^\[([^\]]+)\]\s*/.exec(entry.message);
          return <div key={entry.id} class={`console-event d-flex gap-2 console-event-${entry.tone}`}>
            <time class="console-time">{entry.time}</time><span class="console-kind">{tag?.[1] ?? '系统'}</span><span class="console-message">{tag ? entry.message.slice(tag[0].length) : entry.message}</span>
          </div>;
        })}
      </div>
    </div>
  );
}

function batchProgress(
  state: RequestState<PoolCheckResponse>,
  progress: PoolCheckProgressState | null,
): number {
  if (state.status === 'loading') {
    if (!progress?.total) return 0;
    return Math.round((progress.completed / progress.total) * 100);
  }
  if (state.status === 'ready') return 100;
  return 0;
}

function batchProgressLabel(progress: PoolCheckProgressState | null): string {
  if (!progress?.total) return '正在准备批量检测';
  return `已完成 ${progress.completed} / ${progress.total} 个地址`;
}
