import { useEffect, useRef, useState } from 'preact/hooks';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY, isUserPoolKey, type PoolsResponse } from '../../../src/contracts/pool';
import type { DomainBindingsResponse, MaintenanceRunResponse } from '../../../src/contracts/maintenance';
import type { PoolCheckResponse } from '../../../src/contracts/pool-check';
import type { CheckTargetItemResponse, CheckTargetResponse, HealthResponse, ProbeResponse } from '../../../src/contracts/probe';
import { countPoolFilterMatches, parsePoolFilter, type PoolFilterMode } from '../../../src/domain/pool-filter';
import { countPoolTextLines } from '../../../src/domain/pool-text';
import type { RequestState } from '../state/request-state';
import { Icon, type IconName } from './icon';
import { RecordBadge } from './record-badge';
import { probeStatusLabel } from './probe-status';

/** IP 池写操作的忙碌标记：比起给每个按钮单独维护 loading 状态更省代码。 */
export type PoolActionKey = 'remote-load' | 'filter' | 'remove-lines' | 'pool-edit' | 'clean-pool' | 'trash';
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

/** 所有交互回调集中成一个对象，避免 props 列表随功能增长而失控。 */
export interface DashboardActions {
  readonly lookupSubmit: (event: Event) => void;
  readonly refresh: () => void;
  readonly loadPool: () => void;
  readonly checkBatch: () => void;
  readonly keepAlive: () => void;
  readonly savePool: () => void;
  readonly loadRemote: () => void;
  readonly applyFilter: (mode: PoolFilterMode) => void;
  readonly dedupe: () => void;
  readonly removeLines: () => void;
  readonly createPool: () => void;
  readonly renamePool: () => void;
  readonly movePool: (delta: number) => void;
  readonly deletePool: () => void;
  readonly cleanPool: () => void;
  readonly restoreTrash: () => void;
  readonly clearTrash: () => void;
  readonly bindPool: (key: string, poolKey: string) => void;
  /** 上/下移一条绑定；顺序由服务端整体校验后保存。 */
  readonly moveBinding: (index: number, delta: number) => void;
  readonly refreshBindings: () => void;
  readonly runMaintenance: () => void;
}

interface DashboardPageProps {
  readonly health: RequestState<HealthResponse>;
  readonly check: RequestState<CheckTargetResponse>;
  readonly pools: RequestState<PoolsResponse>;
  readonly batch: RequestState<PoolCheckResponse>;
  readonly lookup: string;
  readonly ipText: string;
  readonly probeConfigured: boolean;
  readonly filterText: string;
  readonly remoteUrl: string;
  readonly poolKey: string;
  readonly loadingPool: boolean;
  readonly checkingBatch: boolean;
  readonly savingPool: boolean;
  readonly poolBusy: PoolActionKey | null;
  readonly consoleLogs: readonly ConsoleLogEntry[];
  readonly batchProgressState: PoolCheckProgressState | null;
  readonly bindings: RequestState<DomainBindingsResponse>;
  readonly maintenance: RequestState<MaintenanceRunResponse>;
  readonly maintenanceBusy: boolean;
  readonly actions: DashboardActions;
  readonly onLookupChange: (value: string) => void;
  readonly onIpTextChange: (value: string) => void;
  readonly onFilterChange: (value: string) => void;
  readonly onRemoteUrlChange: (value: string) => void;
  readonly onPoolChange: (key: string) => void;
}

interface PoolOption {
  readonly key: string;
  readonly name: string;
  readonly count?: number;
}

export function DashboardPage({
  health,
  check,
  pools,
  batch,
  lookup,
  ipText,
  probeConfigured,
  filterText,
  remoteUrl,
  poolKey,
  loadingPool,
  checkingBatch,
  savingPool,
  poolBusy,
  consoleLogs,
  batchProgressState,
  bindings,
  maintenance,
  maintenanceBusy,
  actions,
  onLookupChange,
  onIpTextChange,
  onFilterChange,
  onRemoteUrlChange,
  onPoolChange,
}: DashboardPageProps) {
  const [filterHelpOpen, setFilterHelpOpen] = useState(false);
  const busy = poolBusy !== null;
  const inTrash = poolKey === TRASH_POOL_KEY;

  return (
    <div id="page-dashboard" class="page-panel active" role="tabpanel" aria-labelledby="tab-dashboard">
      <div class="card p-3 probe-overview-card">
        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
          <h2 class="card-title m-0 fw-bold"><Icon name="activity" /> 解析实况</h2>
          <form class="d-flex gap-2 align-items-center flex-grow-1 ddns-lookup-form" onSubmit={actions.lookupSubmit}>
            <input
              type="text"
              class="form-control form-control-sm"
              placeholder="探测: 域名 / IP:端口"
              aria-label="要探测的域名或 IP"
              value={lookup}
              onInput={(event) => onLookupChange(event.currentTarget.value)}
              autocomplete="off"
              spellcheck={false}
            />
            <button
              class="btn btn-primary btn-sm"
              type="submit"
              disabled={check.status === 'loading'}
            >
              <Icon name="search" /> {check.status === 'loading' ? '探测中…' : '探测'}
            </button>
            <button
              class="btn btn-outline-secondary btn-sm"
              type="button"
              onClick={actions.refresh}
            >
              <Icon name="refresh" /> 刷新
            </button>
          </form>
        </div>

        <div id="status-display" class="scroll-box status-display">
          <div class="table-responsive">
            <table class="table text-center mb-0 status-table">
              <thead class="status-table-head">
                <tr>
                  <th>目标地址</th>
                  <th>Colo</th>
                  <th>延迟</th>
                  <th>状态</th>
                  <th>出口IP / 线路</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody id="status-table">
                <StatusRow state={check} />
              </tbody>
            </table>
          </div>
          <div id="txt-status" />
        </div>
      </div>

      <div class="row dashboard-core-row">
        <div class="col-lg-7">
          <div class="card p-4 dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
              <div>
                <h2 class="card-title m-0 fw-bold"><Icon name="database" /> IP 池工作台</h2>
                <p class="dashboard-section-hint">粘贴、筛选并检测节点。检测结果先在本页展示，确认后再入库。</p>
              </div>
              <div class="pool-tools">
                <select
                  id="pool-selector"
                  class="form-select form-select-sm"
                  value={poolKey}
                  aria-label="选择 IP 池"
                  onChange={(event) => onPoolChange(event.currentTarget.value)}
                >
                  {poolOptions(pools, poolKey).map((pool) => (
                    <option key={pool.key} value={pool.key}>
                      {pool.count === undefined ? pool.name : `${pool.name} (${pool.count})`}
                    </option>
                  ))}
                </select>
                <PoolActionMenu busy={busy} inTrash={inTrash} actions={actions} />
              </div>
            </div>

            <div class="ip-content-area">
              <div class="toolbar-row mb-2">
                <input
                  type="text"
                  id="remote-url"
                  class="form-control form-control-sm flex-grow-1"
                  placeholder="远程TXT URL"
                  aria-label="远程 TXT URL"
                  value={remoteUrl}
                  onInput={(event) => onRemoteUrlChange(event.currentTarget.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') actions.loadRemote();
                  }}
                />
                <button
                  class="btn btn-sm btn-outline-primary text-nowrap"
                  type="button"
                  title="从远程URL加载"
                  aria-label="从远程 URL 加载"
                  disabled={poolBusy === 'remote-load'}
                  onClick={actions.loadRemote}
                >
                  <Icon name="download" /> {poolBusy === 'remote-load' ? '加载中…' : '加载'}
                </button>
                <button
                  class="btn btn-sm btn-outline-secondary"
                  type="button"
                  disabled={loadingPool}
                  onClick={actions.loadPool}
                >
                  <Icon name="database" /> {loadingPool ? '读取中…' : '从库'}
                </button>
                <button
                  class="btn btn-sm btn-outline-danger text-nowrap"
                  type="button"
                  disabled={!ipText}
                  onClick={() => onIpTextChange('')}
                >
                  清空
                </button>
              </div>

              <textarea
                id="ip-input"
                class="form-control ip-input mb-2"
                rows={6}
                value={ipText}
                aria-label="IP 池文本"
                onInput={(event) => onIpTextChange(event.currentTarget.value)}
                placeholder={`支持地址、逗号、竖线、Tab、空格混合输入：\n1.2.3.4:443, 1.2.3.5:8443 | [2001:db8::1]:443\n1.2.3.4 (默认443端口)\n1.2.3.4:443,AS64500,US,v4 # HK 香港节点`}
              />

              {!probeConfigured && (
                <div class="kv-alert compact">
                  尚未配置主复检或备用复检接口。检测会返回“探针异常”，请先在配置中心保存检测接口。
                </div>
              )}

              <BatchResults
                state={batch}
                progress={batchProgressState}
                onKeepAlive={actions.keepAlive}
              />

              <div class="mb-2 filter-toolbar">
                <div class="filter-line">
                  <input
                    type="text"
                    id="universal-filter"
                    class="form-control form-control-sm"
                    placeholder="筛选"
                    aria-label="筛选条件"
                    value={filterText}
                    onInput={(event) => onFilterChange(event.currentTarget.value)}
                  />
                  <button
                    class="filter-help-btn"
                    type="button"
                    title="筛选用法"
                    aria-label="查看筛选用法"
                    aria-expanded={filterHelpOpen}
                    onClick={() => setFilterHelpOpen((open) => !open)}
                  >
                    <Icon name="help" />
                  </button>
                  <button class="btn btn-sm btn-outline-success" type="button" title="保留匹配的IP" disabled={busy} onClick={() => actions.applyFilter('keep')}>保留</button>
                  <button class="btn btn-sm btn-outline-danger" type="button" title="排除匹配的IP" disabled={busy} onClick={() => actions.applyFilter('exclude')}>排除</button>
                  <button class="btn btn-sm btn-outline-secondary" type="button" disabled={busy} onClick={actions.dedupe}>去重</button>
                </div>
                <div id="filter-help" class="filter-help" hidden={!filterHelpOpen}>
                  支持空格分隔条件：<code>port:443</code>、<code>port:443-2053</code>、<code>country:国家代码</code>、<code>asn:ASN编号</code>、<code>stack:v4</code>、<code>stack:v6</code>、<code>stack:dual</code>（双栈，等同 v4/v6）、普通关键词。<br />
                  空格表示“且”；逗号表示同一条件内“或”（如 <code>country:US,KR</code> 即美国或韩国）；竖线 <code>|</code> 表示整段之间“或”，优先级最低（先算空格和逗号，最后算 <code>|</code>）。<br />
                  例如：<code>country:US,KR stack:v4</code>（美国或韩国，且出口为IPv4）；<code>country:KR asn:AS4766 | country:US</code>（韩国且ASN为AS4766，或者美国，两者满足其一即可）。
                </div>
                <div id="filter-preview" class="filter-preview">{filterPreviewText(ipText, filterText)}</div>
                <span class="text-secondary small pool-stat" title="当前池中IP数量">
                  共 <span id="pool-count">{currentPoolCount(pools, poolKey)}</span> 条
                </span>
              </div>
            </div>

            <div class="ip-actions-area mt-auto">
              <div class="primary-actions" id="main-actions">
                <button
                  class="btn btn-primary"
                  type="button"
                  aria-label="批量检测输入框中的 IP"
                  disabled={checkingBatch || !ipText.trim()}
                  onClick={actions.checkBatch}
                >
                  <Icon name="activity" /> {checkingBatch ? '检测中…' : '检测'}
                </button>
                <button
                  class="btn btn-success"
                  type="button"
                  aria-label="将输入框内容保存到当前 IP 池"
                  title={inTrash ? '垃圾桶只能由维护和洗库流程写入' : undefined}
                  disabled={savingPool || inTrash || !ipText.trim()}
                  onClick={actions.savePool}
                >
                  <Icon name="save" /> {savingPool ? '保存中…' : '入库'}
                </button>
                <button
                  class="btn btn-outline-secondary btn-sm"
                  type="button"
                  disabled={busy || !ipText.trim()}
                  onClick={actions.removeLines}
                >
                  从库中移除
                </button>
              </div>

              {inTrash && (
                <div id="trash-actions" class="mt-2">
                  <div class="row g-2">
                    <div class="col-6">
                      <button class="btn btn-outline-success btn-sm w-100" type="button" disabled={busy || !ipText.trim()} onClick={actions.restoreTrash}>恢复输入框中的地址</button>
                    </div>
                    <div class="col-6">
                      <button class="btn btn-outline-danger btn-sm w-100" type="button" disabled={busy} onClick={actions.clearTrash}>清空垃圾桶</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div class="col-lg-5">
          <div class="card p-4 dashboard-card dashboard-console-card">
            <div class="dashboard-section-heading">
              <div>
                <h2 class="card-title mb-1 fw-bold"><Icon name="dashboard" /> 运行活动</h2>
                <p class="dashboard-section-hint mb-0">检测、池操作和维护的结果会按时间记录。</p>
              </div>
              <span class="dashboard-section-tag">LIVE</span>
            </div>
            <Console health={health} pools={pools} logs={consoleLogs} />
            <button
              class="btn btn-dark w-100 mb-3"
              type="button"
              disabled={maintenanceBusy}
              onClick={actions.runMaintenance}
            >
              <Icon name="settings" /> {maintenanceBusy ? '维护中…' : '执行全部维护'}
            </button>
            <MaintenanceSummary state={maintenance} />
          </div>
        </div>
        <div class="col-12">
          <DomainBindingsCard bindings={bindings} pools={pools} actions={actions} />
        </div>
      </div>
    </div>
  );
}

/**
 * 批量检测的可见结果面板。
 *
 * 检测完成后保留用户的原始输入，由用户明确选择“仅保留可用”；
 * 失效和探针异常分别展示，避免异常响应被静默当成节点失效。
 */
function BatchResults({
  state,
  progress,
  onKeepAlive,
}: {
  readonly state: RequestState<PoolCheckResponse>;
  readonly progress: PoolCheckProgressState | null;
  readonly onKeepAlive: () => void;
}) {
  if (state.status === 'idle') return null;

  const percent = batchProgress(state, progress);
  const ready = state.status === 'ready' ? state.data : null;
  return (
    <section class="batch-result-panel" data-testid="batch-results" aria-labelledby="batch-result-title">
      <div class="batch-result-head">
        <div>
          <h3 id="batch-result-title" class="batch-result-title">检测结果</h3>
          <p class="batch-result-caption">
            {state.status === 'loading'
              ? batchProgressLabel(progress)
              : ready
                ? '结果已就绪。输入框保持不变，可先查看异常原因再决定是否筛选。'
                : '检测没有完成，请根据错误信息处理后重试。'}
          </p>
        </div>
        {ready && (
          <button
            class="btn btn-sm btn-primary"
            type="button"
            data-action="keep-alive"
            disabled={ready.alive === 0}
            onClick={onKeepAlive}
          >
            仅保留可用
          </button>
        )}
      </div>

      {state.status === 'loading' && (
        <div
          class="progress batch-progress"
          role="progressbar"
          aria-label="批量检测进度"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent}
          aria-valuetext={batchProgressLabel(progress)}
        >
          <div class="progress-bar batch-progress-bar" style={{ width: `${percent}%` }} />
        </div>
      )}

      {state.status === 'error' && <p class="batch-result-error">{state.message}</p>}

      {ready && (
        <>
          <div class="batch-result-summary" aria-label="检测汇总">
            <span class="batch-result-stat"><strong>{ready.total}</strong><small>检测</small></span>
            <span class="batch-result-stat success"><strong>{ready.alive}</strong><small>可用</small></span>
            <span class="batch-result-stat danger"><strong>{ready.dead}</strong><small>失效</small></span>
            <span class="batch-result-stat warning"><strong>{ready.unknown}</strong><small>异常</small></span>
          </div>

          <div class="batch-result-list" role="list" aria-label="逐项检测结果">
            {ready.items.map((item) => (
              <div class="batch-result-row" role="listitem" key={item.address}>
                <ProbeBadge status={item.status} />
                <code class="batch-result-address">{item.address}</code>
                <span class="batch-result-latency">
                  {item.latencyMs === undefined ? item.exitFamily : `${item.latencyMs} ms`}
                </span>
                <span class="batch-result-message" title={item.message ?? item.code}>
                  {batchItemDetail(item)}
                </span>
              </div>
            ))}
          </div>

          {ready.invalid.length > 0 && (
            <details class="batch-invalid">
              <summary>{ready.invalid.length} 条输入无法识别</summary>
              <pre>{ready.invalid.join('\n')}</pre>
            </details>
          )}
        </>
      )}
    </section>
  );
}

function batchItemDetail(item: PoolCheckResponse['items'][number]): string {
  const metadata = [item.country, item.asn ? `AS${item.asn.replace(/^AS/i, '')}` : undefined, item.exitIp]
    .filter(Boolean)
    .join(' · ');
  return [item.message, item.code, metadata].filter(Boolean).join(' · ') || '检测完成';
}

/**
 * IP 池的六个动作收进一个菜单：原来一排纯图标按钮既挤又难认，
 * 改成"文字 + 小图标"后既可读也留出了键盘可达的名称。
 */
function PoolActionMenu({
  busy,
  inTrash,
  actions,
}: {
  readonly busy: boolean;
  readonly inTrash: boolean;
  readonly actions: DashboardActions;
}) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: MouseEvent): void => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  // 菜单项执行后立刻收起，避免停留在"已关掉的菜单"上。
  const run = (action: () => void): void => {
    setOpen(false);
    action();
  };

  // 菜单项形状完全一致，用一张表描述：图标、文案、是否要求已选中池、是否危险、执行动作。
  const items: readonly (readonly [IconName, string, boolean, boolean, () => void])[] = [
    ['plus', '新建池', false, false, actions.createPool],
    ['settings', '重命名当前池', true, false, actions.renamePool],
    ['up', '上移当前池', true, false, () => actions.movePool(-1)],
    ['down', '下移当前池', true, false, () => actions.movePool(1)],
    ['refresh', '一键洗库', true, false, actions.cleanPool],
    ['trash', '删除当前池', true, true, actions.deletePool],
  ];

  return (
    <div class="action-menu" ref={container}>
      <button
        class="btn btn-sm btn-outline-secondary action-menu-trigger"
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        IP 池操作 <Icon name="chevron" />
      </button>
      {open && (
        <div class="action-menu-panel" role="menu" aria-label="IP 池操作">
          {items.map(([icon, label, needsPool, danger, action]) => (
            <button
              key={label}
              class={`action-menu-item${danger ? ' danger' : ''}`}
              type="button"
              role="menuitem"
              disabled={busy || (needsPool && inTrash)}
              onClick={() => run(action)}
            >
              <Icon name={icon} /> {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusRow({ state }: { readonly state: RequestState<CheckTargetResponse> }) {
  if (state.status === 'idle') {
    return <EmptyStatusRow text="暂无解析记录。" />;
  }
  if (state.status === 'loading') {
    return <EmptyStatusRow text="正在检测…" />;
  }
  if (state.status === 'error') {
    return (
      <tr>
        <td colspan={6} class="text-danger py-4">{state.message}</td>
      </tr>
    );
  }

  const { source, items } = state.data;
  // 解析出来的目标可能是多个地址，逐行展示，解析来源放在首行提示里。
  const hint = source.kind === 'direct'
    ? null
    : `${source.kind === 'txt' ? 'txt@' : ''}${source.host ?? ''} 解析到 ${items.length} 个地址`;
  return (
    <>
      {hint && (
        <tr>
          <td colspan={6} class="text-secondary small py-2">{hint}</td>
        </tr>
      )}
      {items.map((item) => <StatusItemRow key={item.address} item={item} />)}
    </>
  );
}

function StatusItemRow({ item }: { readonly item: CheckTargetItemResponse }) {
  const { result } = item;
  return (
    <tr>
      <td class="fw-bold" data-label="目标">{item.address}</td>
      <td data-label="Colo">—</td>
      <td data-label="延迟">{result.latencyMs === undefined ? '—' : `${result.latencyMs} ms`}</td>
      <td data-label="状态"><ProbeBadge status={result.status} /></td>
      <td class="text-start status-exit-cell" data-label="出口">{formatExits(result)}</td>
      <td data-label="结果">{result.code ?? '—'}</td>
    </tr>
  );
}

function EmptyStatusRow({ text }: { readonly text: string }) {
  return (
    <tr>
      <td colspan={6} class="text-secondary py-4">{text}</td>
    </tr>
  );
}

function ProbeBadge({ status }: { readonly status: ProbeResponse['status'] }) {
  return <span class={`record-badge ddns-probe-${status}`}>{probeStatusLabel(status)}</span>;
}

function Console({ health, pools, logs }: {
  readonly health: RequestState<HealthResponse>;
  readonly pools: RequestState<PoolsResponse>;
  readonly logs: readonly ConsoleLogEntry[];
}) {
  const consoleRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = consoleRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [logs]);

  return (
    <div id="log-window" class="console mb-3" role="log" aria-live="polite" aria-relevant="additions text" ref={consoleRef}>
      <div class="console-head">
        <span class="console-line console-dim">DDNS Pro · Cloudflare Worker</span>
        <span class="console-live"><span class="console-live-dot" />实时日志</span>
      </div>
      <div class="console-status-row">
        <span class={`console-status ${health.status === 'ready' ? 'console-status-ok' : health.status === 'error' ? 'console-status-error' : ''}`}>
          API {health.status === 'ready' ? '在线' : health.status === 'error' ? '异常' : '连接中'}
          {health.status === 'ready' ? ` · v${health.data.version} · ${configSourceLabel(health.data.configSource)}` : ''}
        </span>
        <span class={`console-status ${pools.status === 'ready' ? 'console-status-ok' : pools.status === 'error' ? 'console-status-error' : ''}`}>
          IP 池 {pools.status === 'ready' ? `· ${pools.data.pools.length} 个` : pools.status === 'error' ? '读取异常' : '读取中'}
        </span>
      </div>
      <div class="console-event-list">
        {logs.length === 0 && <div class="console-empty">执行探测、池操作或维护后，过程日志会显示在这里。</div>}
        {logs.map((entry) => (
          <div key={entry.id} class={`console-event console-event-${entry.tone}`}>
            <time class="console-time">{entry.time}</time>
            <span class="console-level">{consoleToneLabel(entry.tone)}</span>
            <span class="console-message">{entry.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function consoleToneLabel(tone: ConsoleTone): string {
  if (tone === 'success') return 'OK';
  if (tone === 'warning') return 'WARN';
  if (tone === 'error') return 'ERR';
  return 'INFO';
}

function DomainBindingsCard({
  bindings,
  pools,
  actions,
}: {
  readonly bindings: RequestState<DomainBindingsResponse>;
  readonly pools: RequestState<PoolsResponse>;
  readonly actions: DashboardActions;
}) {
  const [sortingBindings, setSortingBindings] = useState(false);

  return (
    <details class="card p-4 mb-3 domain-binding-card">
      <summary class="domain-binding-header" title="点击展开/折叠域名池绑定">
        <div class="domain-binding-title">
          <h2 class="card-title m-0 fw-bold"><Icon name="globe" /> 域名池绑定</h2>
          {bindings.status === 'ready' && <span class="text-secondary small">{bindings.data.items.length} 个目标</span>}
        </div>
        <div class="domain-binding-actions">
          {bindings.status === 'ready' && bindings.data.items.length > 1 && (
            <button
              class={`btn btn-sm btn-outline-primary${sortingBindings ? ' active' : ''}`}
              type="button"
              aria-pressed={sortingBindings}
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                setSortingBindings((current) => !current);
              }}
            >
              {sortingBindings ? '完成排序' : '调整顺序'}
            </button>
          )}
          <button
            class="btn btn-sm btn-outline-secondary"
            type="button"
            aria-label="刷新域名池绑定"
            title="刷新域名池绑定"
            disabled={bindings.status === 'loading'}
            onClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              actions.refreshBindings();
            }}
          >
            <Icon name="refresh" />
          </button>
        </div>
      </summary>
      {bindings.status === 'loading' && <p class="text-secondary small mb-0">正在读取绑定…</p>}
      {bindings.status === 'error' && <p class="text-danger small mb-0">{bindings.message}</p>}
      {bindings.status === 'ready' && (
        bindings.data.items.length === 0 ? (
          <p class="text-secondary small mb-0">还没有维护目标；请先到“域名管理”创建域名配置。</p>
        ) : (
          <div class="domain-binding-table-wrap">
            <table class={`table table-sm mb-0${sortingBindings ? ' binding-sorting' : ''}`}>
              <thead>
                <tr>
                  <th>域名</th>
                  <th>IP 池</th>
                  {sortingBindings && <th class="domain-binding-order-col">顺序</th>}
                </tr>
              </thead>
              <tbody>
                {bindings.data.items.map((item, index) => (
                  <tr key={item.key}>
                    <td>
                      <div class="domain-binding-domain">
                        <RecordBadge mode={item.mode} />
                        <span class="domain-binding-name" title={item.domain}>{item.domain}</span>
                      </div>
                    </td>
                    <td>
                      <select
                        class="form-select form-select-sm domain-binding-select"
                        value={item.poolKey}
                        disabled={!item.enabled}
                        aria-label={`${item.domain} 绑定的 IP 池`}
                        onChange={(event) => actions.bindPool(item.key, event.currentTarget.value)}
                      >
                        {poolOptions(pools, item.poolKey).filter((pool) => isUserPoolKey(pool.key)).map((pool) => (
                          <option key={pool.key} value={pool.key}>{pool.name}</option>
                        ))}
                      </select>
                    </td>
                    {sortingBindings && (
                      <td class="domain-binding-order-col">
                        <div class="domain-binding-order-actions">
                          <button
                            type="button"
                            class="binding-order-btn"
                            title={`上移 ${item.domain}`}
                            aria-label={`上移 ${item.domain}`}
                            disabled={index === 0}
                            onClick={() => actions.moveBinding(index, -1)}
                          >
                            ↑
                          </button>
                          <button
                            type="button"
                            class="binding-order-btn"
                            title={`下移 ${item.domain}`}
                            aria-label={`下移 ${item.domain}`}
                            disabled={index === bindings.data.items.length - 1}
                            onClick={() => actions.moveBinding(index, 1)}
                          >
                            ↓
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </details>
  );
}

/** 复用领域层的筛选解析与匹配，前端不再维护第二套语法。 */
function filterPreviewText(ipText: string, filterText: string): string {
  if (!filterText.trim()) return '输入条件后会显示匹配数量。';
  const filter = parsePoolFilter(filterText);
  if (!filter) return '筛选条件无效：端口需为 1-65535 的数字或范围。';
  return `匹配 ${countPoolFilterMatches(ipText, filter)} 条，输入框内共 ${countPoolTextLines(ipText)} 条。`;
}

function poolOptions(state: RequestState<PoolsResponse>, currentKey: string): readonly PoolOption[] {
  const options: PoolOption[] = [
    { key: DEFAULT_POOL_KEY, name: '默认池' },
    { key: TRASH_POOL_KEY, name: '垃圾桶' },
  ];
  if (state.status === 'ready') {
    for (const pool of state.data.pools) {
      if (!options.some((option) => option.key === pool.key)) options.push({ key: pool.key, name: pool.name, count: pool.count });
    }
  }
  if (!options.some((option) => option.key === currentKey)) options.push({ key: currentKey, name: currentKey });
  return options.sort((left, right) => poolRank(left.key) - poolRank(right.key) || left.name.localeCompare(right.name, 'zh-CN'));
}

function poolRank(key: string): number {
  if (key === DEFAULT_POOL_KEY) return 0;
  if (key === TRASH_POOL_KEY) return 2;
  return 1;
}

function currentPoolCount(state: RequestState<PoolsResponse>, key: string): number | string {
  if (state.status !== 'ready') return '—';
  return state.data.pools.find((pool) => pool.key === key)?.count ?? 0;
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

function formatExits(result: ProbeResponse): string {
  if (result.exits.length) {
    return result.exits
      .map((exit) => [exit.ip, exit.family, exit.country, exit.asn].filter(Boolean).join(' · '))
      .join(' / ');
  }
  return result.exitIp ?? '未返回出口信息';
}

function configSourceLabel(source: HealthResponse['configSource']): string {
  if (source === 'kv') return 'KV 配置';
  if (source === 'env') return '环境变量';
  return '未提供';
}

/** 维护结果只展示面板关心的字段；探针异常必须与“节点失效”区分显示。 */
function MaintenanceSummary({ state }: { readonly state: RequestState<MaintenanceRunResponse> }) {
  if (state.status === 'idle') return null;
  if (state.status === 'loading') return <p class="text-secondary small mb-3">正在执行维护，请保持页面打开…</p>;
  if (state.status === 'error') return <p class="text-danger small mb-3">{state.message}</p>;

  const { data } = state;
  const warning = data.errors.length > 0 || data.probeErrors > 0;
  return (
    <div class="maintenance-summary small mb-3">
      <div class={warning ? 'text-warning' : 'text-secondary'}>
        {data.changed ? '维护完成：DNS 已更新' : '维护完成：无需变更'}
        {data.insufficient ? ' · 可用 IP 不足' : ''}
        {data.probeErrors > 0 ? ` · ${data.probeErrors} 次探针异常（未计为失效）` : ''}
      </div>
      {data.results.map((item) => (
        <div key={`${item.domain}|${item.mode}`} class="maintenance-result">
          <RecordBadge mode={item.mode} />
          <span class="domain-binding-name" title={item.domain}>{item.domain}</span>
          <span class="text-secondary">+{item.added} / -{item.deleted}</span>
          {item.probeErrors > 0 && <span class="text-warning">探针异常 {item.probeErrors} 次</span>}
          {item.error && <span class="text-danger">{item.error}</span>}
        </div>
      ))}
      {data.errors.map((error) => (
        <div class="text-danger">{error}</div>
      ))}
    </div>
  );
}
