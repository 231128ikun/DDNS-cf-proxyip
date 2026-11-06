import { useLayoutEffect, useRef } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import type { PoolCheckResponse } from '../../../src/contracts/pool-check';
import type { CheckTargetResponse, HealthResponse } from '../../../src/contracts/probe';
import type { ConfigResponse } from '../../../src/contracts/config';
import type { MaintenanceLogLine } from '../../../src/contracts/maintenance';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
import type { RequestState } from '../state/request-state';
import type { TargetStatusView } from '../state/target-status';
import { Icon } from './icon';
import { AddressText } from './address-text';
import { StatusOverview } from './status-overview';
import type { TargetSelectorProps } from './target-selector';

/** 当前忙碌的池写操作。 */
export type PoolActionKey = 'pool-edit';
export type ConsoleTone = MaintenanceLogLine['tone'];
const consoleLevels: Record<ConsoleTone, string> = { info: '信息', success: '成功', warning: '告警', error: '失败' };

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
    <div id="page-dashboard" role="tabpanel" aria-labelledby="tab-dashboard">
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
          <span>默认并发：{config.data.config.settings.CONCURRENT_CHECKS} · 单轮超时：{config.data.config.settings.CHECK_TIMEOUT / 1000}s</span>
          <span>定时维护：{config.data.config.scheduledEnabled ? '开启' : '关闭'}</span>
          <span>Telegram：{config.data.config.tgEnabled ? '开启' : '关闭'}</span>
          <span>维护目标：{config.data.config.targets.filter(target => target.enabled).length} 个</span>
        </div>}
      </div>
      <div class="console-event-list">
        {logs.length === 0 && <div class="console-empty">正在连接系统…</div>}
        {logs.map(entry => {
          const tag = /^\[([^\]]+)\]\s*/.exec(entry.message);
          return <div key={entry.id} class={`console-event console-event-${entry.tone}`}>
            <time class="console-time">{entry.time}</time>{' '}
            <span class="console-kind" title={consoleLevels[entry.tone]}>{tag?.[1] ?? '系统'}</span>{' '}
            <span class="console-message">{highlightLog(tag ? entry.message.slice(tag[0].length) : entry.message)}</span>
          </div>;
        })}
      </div>
    </div>
  );
}

const logOutcome = /(?:^| · )(可用|失效(?:（超时）)?|未知(?:（HTTP 异常）)?|未判定|未确认|筛选不匹配|检测(?:超时|失效))(?= · | \[|$)|^(候选异常|(?:执行|维护|通知发送)失败|未达到最小活跃数)/;
const logAddress = /\[[\da-f:.]+\](?::\d+)?|[\w:][\w.:-]*/gi;

function highlightLog(message: string): ComponentChildren {
  const match = logOutcome.exec(message);
  if (!match) return highlightAddresses(message);
  const outcome = (match[1] ?? match[2])!;
  const end = match.index + match[0].length;
  return <>{highlightAddresses(message.slice(0, end - outcome.length))}<span class="console-outcome">{outcome}</span>{message.slice(end)}</>;
}

function highlightAddresses(message: string): ComponentChildren {
  const parts: ComponentChildren[] = [];
  let start = 0;
  for (const match of message.matchAll(logAddress)) {
    const value = match[0].replace(/\.+$/, '');
    if (!/[.:]/.test(value)) continue;
    const target = parseProxyTarget(value);
    if (!target || (target.family === 'hostname' && !/\.[a-z][a-z\d-]*$/i.test(target.host))) continue;
    parts.push(message.slice(start, match.index), <AddressText key={match.index} value={value} />);
    start = match.index + value.length;
  }
  return parts.length ? [...parts, message.slice(start)] : message;
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
