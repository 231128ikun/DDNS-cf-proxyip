import { useEffect, useRef } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import type { PoolCheckResponse } from '../../../src/contracts/pool-check';
import type { CheckTargetResponse } from '../../../src/contracts/probe';
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
  readonly check: RequestState<CheckTargetResponse>;
  readonly batch: RequestState<PoolCheckResponse>;
  readonly lookup: string;
  readonly consoleLogs: readonly ConsoleLogEntry[];
  readonly batchProgressState: PoolCheckProgressState | null;
  readonly targetStatus: RequestState<TargetStatusView>;
  readonly selectedTargetKey: string | null;
  readonly targetPort: number | 'any';
  readonly maintenanceBusy: boolean;
  readonly actions: DashboardActions;
  readonly onCopyToInput: (address: string) => void;
  readonly onCopyAddress: (address: string) => void;
  readonly onLookupChange: (value: string) => void;
}


export function DashboardPage({
  poolPanel,
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

          <div class="card p-4 dashboard-card dashboard-console-card">
            <div class="dashboard-card-header">
              <h2 class="card-title m-0 fw-bold"><Icon name="dashboard" /> 工作台</h2>
            </div>
            <Console logs={consoleLogs} />
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
              disabled={maintenanceBusy}
              onClick={actions.runMaintenance}
            >
              <Icon name="wrench" /> {maintenanceBusy ? '维护中…' : '执行全部维护'}
            </button>
          </div>
      </div>
    </div>
  );
}

function Console({ logs }: {
  readonly logs: readonly ConsoleLogEntry[];
}) {
  const consoleRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = consoleRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [logs]);

  return (
    <div id="log-window" class="console mb-3" role="log" aria-label="工作台日志" aria-live="polite" aria-relevant="additions text" ref={consoleRef}>
      <div class="console-event-list">
        {logs.length === 0 && <div class="console-empty">正在连接系统…</div>}
        {logs.map((entry) => (
          <div key={entry.id} class={`console-event console-event-${entry.tone}`}>
            [<time class="console-time">{entry.time}</time>{`] ${entry.message}`}
          </div>
        ))}
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
