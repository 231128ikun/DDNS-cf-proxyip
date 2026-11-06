import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { NUMBERED_POOL_KEY_RE, TRASH_POOL_KEY, type PoolsResponse } from '../../../src/contracts/pool';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { matchesPoolFilter, parsePoolFilter } from '../../../src/domain/pool-filter';
import type { ApiClient } from '../api/client';
import { errorMessage } from '../api/errors';
import type { RequestState } from '../state/request-state';
import type { useBatchCheck } from '../state/use-batch-check';
import { PoolWorkspace } from '../state/pool-workspace';
import { poolOptions } from '../state/pool-options';
import { Icon } from './icon';
import { AddressText } from './address-text';
import type { WashProgress } from './dashboard-page';
import { ResourceFeedback } from './resource-feedback';
import { probeStatusLabel } from './probe-status';
import { logProbe, type ConsoleLog } from './probe-log';

interface PoolPanelProps {
  readonly client: ApiClient;
  readonly pools: RequestState<PoolsResponse>;
  readonly poolKey: string;
  readonly onPoolChange: (key: string) => void;
  readonly actions: PoolContainerActions;
  readonly containerBusy: boolean;
  readonly refreshPools: () => void;
  readonly onPoolCount: (key: string, count: number) => void;
  readonly batch: ReturnType<typeof useBatchCheck>;
  readonly configReady: boolean;
  readonly checkConcurrency: number | 'all';
  readonly bindingsReady: boolean;
  readonly probeConfigured: boolean;
  readonly leaveGuard: { current: () => boolean };
  readonly containerChanged: { current: (key: string) => void };
  readonly log: ConsoleLog;
  readonly onWashProgress: (progress: WashProgress | null) => void;
  readonly onWriteBusy: (busy: boolean) => void;
}

/** 输入负责整理和出入库，结果只负责选择。 */
export function PoolPanel({ client, pools, poolKey, onPoolChange, actions, containerBusy, refreshPools,
  onPoolCount, batch, configReady, checkConcurrency, bindingsReady, probeConfigured, leaveGuard, containerChanged, log, onWashProgress, onWriteBusy }: PoolPanelProps) {
  const [, render] = useState(0);
  const model = useMemo(() => new PoolWorkspace(client, () => render(value => value + 1)), [client]);
  const [view, setView] = useState<'input' | 'results'>('input');
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [url, setUrl] = useState('');
  const [urlOpen, setUrlOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [sideBusy, setSideBusy] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const cleanController = useRef<AbortController | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const poolMenu = useRef<HTMLDetailsElement>(null);
  const source = useRef<AbortController | null>(null);
  const sidePending = useRef(false);
  const report = batch.batchReport;
  const inTrash = poolKey === TRASH_POOL_KEY;
  const locked = containerBusy || model.writing || loading || sideBusy || batch.checkingBatch;
  const refreshingPools = pools.status === 'loading' || (pools.status === 'ready' && pools.refreshing === true);
  const filter = useMemo(() => query.trim() ? parsePoolFilter(query) : null, [query]);
  const badFilter = Boolean(query.trim() && !filter);
  const matches = useCallback((line: string): boolean => !query.trim() || Boolean(filter && matchesPoolFilter(line, filter)), [query, filter]);
  const inputText = useMemo(() => batch.ipText.split(/\r?\n/).filter(matches).join('\n'), [batch.ipText, matches]);
  const inputSnapshot = useMemo(() => readPoolSnapshot(inputText), [inputText]);
  const invalid = inputSnapshot.invalid;
  const inputCount = inputSnapshot.entries.size;
  const rows = useMemo(() => report ? [
    ...report.items.map(item => ({ key: item.address, line: item.line, label: item.address, status: item.status,
      detail: [
        [item.colo, ''],
        [item.latencyMs === undefined ? '' : `${item.latencyMs}ms`, 'syntax-number'],
        [item.exitFamily === 'dual' ? 'IPv4/IPv6' : item.exitFamily === 'unknown' ? '' : item.exitFamily.toUpperCase(), 'syntax-type'],
        [item.country, ''],
        [item.city || item.region, ''],
        [item.asn, 'syntax-meta'],
      ] as const,
      reason: item.status === 'alive' ? '' : item.message ?? item.code ?? '',
    })),
    ...report.invalid.map(line => ({ key: line, line, label: line, status: 'invalid', detail: [], reason: '' })),
    ...report.incomplete.map(line => ({ key: line, line, label: line, status: 'incomplete', detail: [], reason: '' })),
  ].filter(item => matches(item.line)) : [], [report, matches]);
  const shown = useMemo(() => rows.filter(item => category === 'all' || item.status === category), [rows, category]);
  const selectedRows = useMemo(() => rows.filter(item => selected.has(item.key)), [rows, selected]);
  const options = poolOptions(pools, poolKey);
  const selectedPool = options.find(pool => pool.key === poolKey);
  const count = useMemo(() => selectedPool?.count ?? (model.content === undefined ? undefined : readPoolSnapshot(model.content).entries.size),
    [selectedPool?.count, model.content]);
  const name = selectedPool?.name ?? poolKey;
  const statusName = (status: string): string => ({ all: '全部', alive: '可用', dead: '失效', unknown: '异常', invalid: '无效', incomplete: '未完成' })[status] ?? status;

  leaveGuard.current = () => !model.writing && !sidePending.current;
  containerChanged.current = key => model.forgetPool(key);
  useLayoutEffect(() => { model.select(poolKey); }, [poolKey, model]);
  useEffect(() => () => { source.current?.abort(); cleanController.current?.abort(); model.dispose(); }, [model]);
  useEffect(() => {
    const dismiss = (event: PointerEvent): void => {
      const menu = poolMenu.current;
      if (menu?.open && !menu.contains(event.target as Node)) menu.open = false;
    };
    document.addEventListener('pointerdown', dismiss);
    return () => document.removeEventListener('pointerdown', dismiss);
  }, []);
  useEffect(() => { onWriteBusy(sideBusy || model.writing); }, [sideBusy, model.writing, onWriteBusy]);
  useEffect(() => { setSelected(new Set()); setCategory('all'); if (report) setView('results'); }, [report?.source]);
  useEffect(() => { if (!report) { setView('input'); setSelected(new Set()); } }, [report]);
  useEffect(() => { if (batch.checkingBatch) { setSelected(new Set()); setCategory('all'); setView('results'); } }, [batch.checkingBatch]);

  const changeInput = (text: string): void => { model.invalidate(); batch.replaceIpText(text); setView('input'); };
  const load = async (read: (signal: AbortSignal) => Promise<string>): Promise<void> => {
    if (locked || source.current) return;
    if (batch.ipText && !window.confirm('载入会替换输入内容，继续？')) return;
    const controller = source.current = new AbortController(), revision = model.revision;
    setLoading(true);
    try {
      const text = await read(controller.signal);
      if (controller.signal.aborted || revision !== model.revision) return;
      setQuery(''); changeInput(text); model.message = ''; setUrlOpen(false);
    } catch (error) {
      if (!controller.signal.aborted) { model.message = errorMessage(error); log('[IP池] ' + model.message, 'error'); }
    } finally { if (source.current === controller) { source.current = null; setLoading(false); } }
  };
  const loadPool = (): void => { void load(async () => {
    const text = await model.read();
    if (text === undefined) throw new Error(model.message || '读取失败');
    onPoolCount(poolKey, readPoolSnapshot(text).entries.size);
    return text;
  }); };
  const loadFile = (file: File | undefined): void => {
    if (!file) return;
    if (file.size > 512_000) { model.message = '文件过大，请分批导入'; render(value => value + 1); return; }
    void load(() => file.text());
  };
  const download = (): void => {
    const text = view === 'results' ? rows.map(item => item.line).join('\n') : inputText;
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = `${poolKey}.txt`; link.click(); URL.revokeObjectURL(url);
  };
  const write = async (mode: 'append' | 'remove'): Promise<void> => {
    if (locked || sidePending.current || badFilter || invalid.length || !inputCount || inTrash) return;
    if (mode === 'remove' && !window.confirm(`从「${name}」剔除输入中的 ${inputCount} 个地址？按地址和端口匹配，其余内容保留。`)) return;
    sidePending.current = true;
    try {
      const saved = await model.save(inputText, mode);
      if (saved && model.content !== undefined) onPoolCount(poolKey, readPoolSnapshot(model.content).entries.size);
      log('[IP池] ' + model.message, saved ? 'success' : 'error');
    } finally { sidePending.current = false; }
  };
  const runTrash = async (clear = false): Promise<void> => {
    if (locked || sidePending.current) return;
    const addresses = [...readPoolSnapshot(inputText).entries.keys()];
    if (!clear && !addresses.length) return;
    if (clear && !window.confirm('清空垃圾桶？此操作不可撤销。')) return;
    sidePending.current = true; setSideBusy(true);
    try {
      if (clear) { await client.clearTrash(); model.message = '垃圾桶已清空'; }
      else { const result = await client.restoreTrash(addresses, { restoreToSource: true }); model.message = `已恢复 ${result.restored} 条`; }
      const message = model.message; model.forgetPool(poolKey); model.message = message; refreshPools(); log('[IP池] ' + message, 'success');
    } catch (error) { model.message = errorMessage(error); log('[IP池] ' + model.message, 'error'); }
    finally { sidePending.current = false; setSideBusy(false); }
  };
  const cleanPool = async (): Promise<void> => {
    if (locked || sidePending.current || !window.confirm(`一键洗库「${name}」？${inTrash ? '可用地址恢复到来源池。' : '复检失效的地址移入垃圾桶。'}检测异常时不清理。`)) return;
    sidePending.current = true; setSideBusy(true);
    const controller = cleanController.current = new AbortController();
    setCleaning(true); model.message = '正在读取库存…';
    const progress = (status: string) => onWashProgress({ pool: name, status });
    progress('读取库存…');
    log(`[洗库] 读取库存 · ${name}`);
    try {
      const result = await client.cleanPool(poolKey, controller.signal, event => {
        model.message = `检测中 ${event.completed}/${event.total} · 全部确认后写入`;
        render(value => value + 1);
        progress(event.completed + ' / ' + event.total);
        logProbe(log, '洗库', event.item.address, event.item);
      }, checkConcurrency, () => {
        model.message = '正在核对库存并提交清理…';
        progress('核对库存…');
        render(value => value + 1);
        log('[洗库] 检测完成，正在核对库存并提交清理');
      });
      model.message = result.skipped ? `检测异常或格式无效 ${result.unknown} 条，未清理`
        : `检测 ${result.checked} 条 · ${inTrash ? '恢复' : '保留'} ${result.kept} 条${inTrash ? '' : ` · 入桶 ${result.trashed} 条`}`;
      if (!result.skipped) {
        const message = model.message; model.forgetPool(poolKey); model.message = message;
        if (!inTrash || result.remaining !== undefined) onPoolCount(poolKey, result.remaining ?? result.kept);
      }
      log('[洗库] ' + model.message, result.skipped ? 'warning' : 'success');
    } catch (error) { model.message = controller.signal.aborted ? '洗库已停止，未取得完成确认，请核对库存' : errorMessage(error); log('[洗库] ' + model.message, controller.signal.aborted ? 'warning' : 'error'); }
    finally { onWashProgress(null); cleanController.current = null; sidePending.current = false; setCleaning(false); setSideBusy(false); }
  };
  const choose = (key: string, checked: boolean): void => setSelected(current => {
    const next = new Set(current); if (checked) next.add(key); else next.delete(key); return next;
  });
  const closePoolMenu = (): void => {
    if (poolMenu.current) poolMenu.current.open = false;
    document.getElementById('pool-action-trigger')?.focus();
  };
  const runPoolMenuAction = (action: () => void): void => { closePoolMenu(); action(); };

  return <section class="card dashboard-card dashboard-pool-card pool-workspace" aria-label="IP 库管理">
    <header class="dashboard-card-header pool-header">
      <h2 class="card-title m-0 fw-bold"><Icon name="database" />IP池管理 <small id="pool-count">{count ?? '—'} 条</small></h2>
      <div class="pool-tools">
        <select id="pool-selector" class="form-select form-select-sm" aria-label="选择 IP 池" value={poolKey} disabled={locked}
          onChange={event => { if (leaveGuard.current()) onPoolChange(event.currentTarget.value); }}>{options.map(pool => <option key={pool.key} value={pool.key}>{pool.name}</option>)}</select>
        <button type="button" class="btn btn-sm btn-icon btn-outline-secondary" aria-label="刷新池列表" title="刷新池列表"
          disabled={locked || refreshingPools} aria-busy={refreshingPools} onClick={refreshPools}><Icon name="refresh" /></button>
        <details class="pool-menu" ref={poolMenu} onKeyDown={event => {
          if (event.key === 'Escape' && event.currentTarget.open) { event.preventDefault(); closePoolMenu(); }
        }}>
          <summary id="pool-action-trigger" class="btn btn-sm btn-outline-secondary"><Icon name="settings" />{cleaning ? '洗库中…' : '池操作'} <span aria-hidden="true">▾</span></summary>
          <div class="action-menu-panel" role="group" aria-label="池操作">
            {([['新建池', 'plus', actions.createPool, false], ['重命名', 'pencil', actions.renamePool, inTrash || !bindingsReady],
              ['一键洗库', 'broom', () => void cleanPool(), !configReady || !probeConfigured],
              ['池排序', 'sort', actions.openPoolOrder, false], ['删除池', 'trash', actions.deletePool, !NUMBERED_POOL_KEY_RE.test(poolKey) || !bindingsReady],
            ] as const).map(([label, icon, action, disabled]) => <button key={label} type="button" class={icon === 'trash' ? 'action-menu-item danger' : 'action-menu-item'} title={label === '一键洗库' && !probeConfigured ? '请先配置检测出口' : undefined} data-action={label === '一键洗库' ? 'clean-pool' : undefined} disabled={locked || disabled} onClick={() => runPoolMenuAction(action)}><Icon name={icon} />{label}</button>)}
            {inTrash && <button type="button" class="action-menu-item danger" disabled={locked} onClick={() => runPoolMenuAction(() => void runTrash(true))}><Icon name="trash" />清空垃圾桶</button>}
          </div>
        </details>
      </div>
    </header>
    <ResourceFeedback state={pools} id="retry-pools" onRetry={refreshPools} />
    <div class="pool-editor-toolbar">
      <div class="pool-view-switch" role="group" aria-label="工作区视图">
        <button type="button" class="btn btn-sm btn-outline-secondary" data-action="view-draft" aria-pressed={view === 'input'} onClick={() => setView('input')}>输入</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-action="view-results" aria-pressed={view === 'results'} disabled={!report} onClick={() => setView('results')}>结果 {report?.items.length ?? 0}</button>
      </div>
      <div class="pool-source-actions" role="group" aria-label="导入来源">
        <button type="button" class="btn btn-sm btn-outline-secondary" data-action="load-pool" disabled={locked} onClick={loadPool}><Icon name="database" />从池读取</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" aria-expanded={urlOpen} disabled={locked} onClick={() => setUrlOpen(value => !value)}><Icon name="link" />远程链接</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-action="upload-file" disabled={locked} onClick={() => fileInput.current?.click()}><Icon name="folder" />本地文件</button>
        <input id="pool-file" ref={fileInput} type="file" hidden accept=".txt,.csv,text/plain" aria-label="上传 IP 文本文件" onChange={event => { loadFile(event.currentTarget.files?.[0]); event.currentTarget.value = ''; }} />
      </div>
    </div>
    {urlOpen && <form class="pool-remote" onSubmit={event => { event.preventDefault(); if (url.trim()) void load(async signal => (await client.remoteLoad(url.trim(), signal)).content); }}>
      <input id="remote-url" class="form-control form-control-sm" aria-label="远程 TXT URL" type="url" value={url} placeholder="https://example.com/ips.txt" disabled={locked} onInput={event => setUrl(event.currentTarget.value)} />
      <button type="submit" class="btn btn-sm btn-outline-primary" aria-label="从远程 URL 加载" disabled={locked || !url.trim()}>载入</button>
    </form>}
    <div class="pool-data-body">
      <textarea id="ip-input" class="form-control ip-input" aria-label="IP 输入内容" hidden={view !== 'input'} value={inputText} readOnly={locked || Boolean(query.trim())} spellcheck={false}
        onInput={event => changeInput(event.currentTarget.value)} placeholder={'每行一个地址，例如：\n203.0.113.10:443\n[2001:db8::1]:8443\n203.0.113.20:443,AS64500,JP,v4 # 备用'} />
      {report && <div class="pool-report" hidden={view !== 'results'} aria-label="检测结果">
        <div class="pool-result-tools">
          <select class="form-select form-select-sm" aria-label="检测结果分类" value={category} onChange={event => setCategory(event.currentTarget.value)}>
            {['all', 'alive', 'dead', 'unknown', 'invalid', 'incomplete'].map(status => <option value={status}>{statusName(status)} {status === 'all' ? rows.length : rows.filter(item => item.status === status).length}</option>)}
          </select>
          <label class="pool-select-all"><input type="checkbox" aria-label="选择当前结果" checked={shown.length > 0 && shown.every(item => selected.has(item.key))} disabled={locked || !shown.length}
            onChange={event => { const checked = event.currentTarget.checked; setSelected(current => { const next = new Set(current); for (const item of shown) { if (checked) next.add(item.key); else next.delete(item.key); } return next; }); }} />全选</label>
          <span class="small text-secondary">已选 {selectedRows.length}</span>
        </div>
        <ul class="pool-result-list" aria-label="检测结果列表">{shown.map(item => <li key={item.key}><label>
          <input type="checkbox" aria-label={`选择 ${item.label}`} disabled={locked} checked={selected.has(item.key)} onChange={event => choose(item.key, event.currentTarget.checked)} />
          <span><strong>{item.detail.length ? <AddressText value={item.label} /> : item.label}</strong>
            <small><span class={item.status === 'alive' ? 'text-success' : item.status === 'dead' || item.status === 'invalid' ? 'text-danger' : item.status === 'unknown' ? 'text-warning' : ''}>
              {item.status === 'alive' || item.status === 'dead' || item.status === 'unknown' ? probeStatusLabel(item.status) : statusName(item.status)}
            </span>{item.detail.map(([value, style], index) => value && <span key={index}> · <span class={style}>{value}</span></span>)}</small>
            {item.reason && <small class="pool-diagnostic">{item.reason}</small>}
          </span>
        </label></li>)}{!shown.length && <li class="text-secondary">没有匹配结果</li>}</ul>
      </div>}
    </div>
    <div class="pool-filter-row">
      <input id="draft-filter" class="form-control form-control-sm" aria-label="筛选输入或结果" value={query} placeholder="筛选 IP、国家、ASN 或备注" disabled={locked} onInput={event => { setQuery(event.currentTarget.value); setSelected(new Set()); }} />
      <Help label="筛选用法"><p><code>port:443</code> 端口，<code>port:443-2053</code> 端口范围；<code>country:KR</code> 国家，<code>asn:AS4766</code> ASN，<code>stack:v4</code> / <code>v6</code> / <code>dual</code> 出口栈。</p><p>不同字段用<strong>空格</strong>表示“且”；同一字段用<strong>逗号 ,</strong>表示“或”，如 <code>country:US,KR</code>。</p><p><strong>竖线 |</strong>连接的整组条件表示“或”，最后计算。例如 <code>country:KR asn:AS4766 | country:US</code>。</p><p>普通文字可匹配 IP 或备注；清空筛选恢复原文。</p></Help>
    </div>
    {badFilter && <p role="status" class="text-danger small">筛选条件无效</p>}
    {invalid.length > 0 && view === 'input' && <details class="small text-danger"><summary>无效内容 {invalid.length} 行</summary><pre class="pool-text">{invalid.join('\n')}</pre></details>}
    {model.message && <p class="pool-feedback small" role="status">{model.message}</p>}
    <footer class="pool-footer" id="main-actions">
      <div class="pool-footer-primary" role="group" aria-label="检测和出入库">
      {cleaning && <button type="button" class="btn btn-sm btn-danger" data-action="stop-clean" onClick={() => cleanController.current?.abort()}>停止洗库</button>}
      {view === 'input' ? <>
        <button type="button" class={batch.checkingBatch ? 'btn btn-sm btn-danger' : 'btn btn-sm btn-primary'} aria-label={batch.checkingBatch ? '停止批量检测' : '批量检测导入草稿'} disabled={!batch.checkingBatch && (!configReady || !probeConfigured || locked || badFilter || !inputCount)}
          onClick={() => { if (batch.checkingBatch) batch.handleStopBatch(); else { setView('results'); batch.handleCheckBatch(false, inputText); } }}><Icon name={batch.checkingBatch ? 'stop' : 'activity'} />{batch.checkingBatch ? '停止' : '检测'}</button>
        {inTrash ? <button type="button" class="btn btn-sm btn-success" disabled={locked || badFilter || !inputCount} data-action="restore-trash" onClick={() => void runTrash()}>恢复到来源池</button> : <>
          <button type="button" class="btn btn-sm btn-success" data-action="append-pool" disabled={locked || badFilter || !inputCount || Boolean(invalid.length)} onClick={() => void write('append')}><Icon name="plus" />追加入库</button>
          <button type="button" class="btn btn-sm btn-outline-danger" data-action="remove-input" disabled={locked || badFilter || !inputCount || Boolean(invalid.length)} onClick={() => void write('remove')}>从库剔除</button>
        </>}
      </> : <>{batch.checkingBatch && <button type="button" class="btn btn-sm btn-danger" aria-label="停止批量检测" onClick={batch.handleStopBatch}>停止</button>}<button type="button" class="btn btn-sm btn-primary" data-action="retain-results" disabled={locked || !selectedRows.length} onClick={() => { setQuery(''); changeInput(selectedRows.map(item => item.line).join('\n')); }}>保留到输入 {selectedRows.length || ''}</button></>}
      </div>
      <div class="pool-footer-secondary" role="group" aria-label="输入和导出">
        <button type="button" class="btn btn-sm btn-outline-secondary" disabled={view === 'input' ? !inputText : !rows.length} onClick={download}>导出</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-action="clear-input" disabled={locked || !batch.ipText} onClick={() => { setQuery(''); changeInput(''); }}>清空</button>
      </div>
    </footer>
  </section>;
}

function Help({ label, children }: { readonly label: string; readonly children: ComponentChildren }) {
  const [open, setOpen] = useState(false);
  return <div class="pool-help" onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false); }}
    onKeyDown={event => { if (event.key === 'Escape') setOpen(false); }}>
    <button type="button" class="guide-toggle" aria-label={label} aria-expanded={open} aria-controls="pool-filter-help" onClick={() => setOpen(value => !value)}><Icon name="help" /></button>
    <div id="pool-filter-help" class="pool-help-content" role="region" aria-label={label} hidden={!open}>{children}</div>
  </div>;
}

export interface PoolContainerActions {
  readonly createPool: () => void;
  readonly renamePool: () => void;
  readonly openPoolOrder: () => void;
  readonly deletePool: () => void;
}
