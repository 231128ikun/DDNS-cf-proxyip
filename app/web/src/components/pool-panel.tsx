import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { MAX_POOL_RESTORE_ITEMS, NUMBERED_POOL_KEY_RE, TRASH_POOL_KEY, type PoolsResponse } from '../../../src/contracts/pool';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { matchesPoolFilter, parsePoolFilter } from '../../../src/domain/pool-filter';
import { sourcePoolFromTrash } from '../../../src/domain/trash';
import type { ApiClient } from '../api/client';
import { errorMessage } from '../api/errors';
import type { RequestState } from '../state/request-state';
import type { useBatchCheck } from '../state/use-batch-check';
import { PoolWorkspace, invalidPoolLines } from '../state/pool-workspace';
import { poolOptions } from '../state/pool-options';
import { Icon, type IconName } from './icon';
import { Modal } from './modal';
import type { ConsoleTone } from './dashboard-page';
import { ResourceFeedback } from './resource-feedback';
import { formatProbeLog, shouldLogProbe } from './probe-log';
import { probeStatusLabel } from './probe-status';

interface PoolPanelProps {
  readonly client: ApiClient;
  readonly pools: RequestState<PoolsResponse>;
  readonly poolKey: string;
  readonly onPoolChange: (key: string) => void;
  readonly actions: PoolContainerActions;
  readonly containerBusy: boolean;
  readonly refreshPools: () => void;
  readonly batch: ReturnType<typeof useBatchCheck>;
  readonly configReady: boolean;
  readonly probeConfigured: boolean;
  readonly leaveGuard: { current: () => boolean };
  readonly containerChanged: { current: (key: string) => void };
  readonly log: (message: string, tone?: ConsoleTone) => void;
}

/** The pool card owns drafts and queries; only explicit commands can write. */
export function PoolPanel({ client, pools, poolKey, onPoolChange, actions, containerBusy, refreshPools,
  batch, configReady, probeConfigured, leaveGuard, containerChanged, log }: PoolPanelProps) {
  const [, render] = useState(0);
  const model = useMemo(() => new PoolWorkspace(client, () => render(value => value + 1)), [client]);
  containerChanged.current = key => model.forgetPool(key);
  const [mode, setMode] = useState<'import' | 'manage'>('import');
  const [edit, setEdit] = useState<{ poolKey: string; original: string; text: string } | null>(null);
  const [sourcePool, setSourcePool] = useState<string | null>(null);
  const [url, setUrl] = useState('');
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [sideBusy, setSideBusy] = useState(false);
  const sidePending = useRef(false);
  const remote = useRef<AbortController | null>(null);
  const [filter, setFilter] = useState('');
  const [selection, setSelection] = useState<ReadonlySet<string>>(new Set());
  const [page, setPage] = useState(0);
  const [category, setCategory] = useState('alive');
  const [showResults, setShowResults] = useState(false);
  const dirty = Boolean(edit && edit.text !== edit.original);
  const inTrash = poolKey === TRASH_POOL_KEY;
  const busy = model.writing || sideBusy || containerBusy;
  const inputsLocked = busy || batch.checkingBatch || remoteBusy;
  const managementLocked = busy || model.reading;
  const snapshot = useMemo(() => readPoolSnapshot(model.content ?? ''), [model.content]);
  const query = filter.trim() ? parsePoolFilter(filter) : null;
  const invalidFilter = Boolean(filter.trim() && !query);
  const rows = [...snapshot.entries].filter(([, item]) => !filter.trim() || (query && matchesPoolFilter(item.raw, query)));
  const pages = Math.max(1, Math.ceil(rows.length / 50));
  const currentPage = Math.min(page, pages - 1);
  const shown = rows.slice(currentPage * 50, (currentPage + 1) * 50);
  const report = batch.batchReport;
  const resultsVisible = showResults && report !== null;
  const invalid = useMemo(() => invalidPoolLines(batch.ipText), [batch.ipText]);
  const poolName = (key: string): string => poolOptions(pools, key).find(pool => pool.key === key)?.name ?? key;
  const targetName = poolName(poolKey);
  const count = model.confirmed.get(poolKey)?.count ?? (model.content !== undefined ? snapshot.entries.size
    : pools.status === 'ready' ? pools.data.pools.find(pool => pool.key === poolKey)?.count : undefined);

  leaveGuard.current = () => {
    if (busy) return false;
    if (dirty && !window.confirm('完整编辑尚未提交，确认放弃编辑并离开？')) return false;
    model.invalidate();
    setEdit(null);
    return true;
  };
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { if (dirty) { event.preventDefault(); event.returnValue = ''; } };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);
  useEffect(() => () => { remote.current?.abort(); model.dispose(); }, [model]);
  useLayoutEffect(() => {
    model.select(poolKey);
    setSelection(new Set()); setFilter(''); setPage(0); setEdit(null);
    if (mode === 'manage' || poolKey === TRASH_POOL_KEY) void model.read();
  }, [poolKey, model]);
  useEffect(() => { model.invalidate(); setCategory('alive'); setShowResults(report !== null); }, [batch.ipText, report, model]);
  useLayoutEffect(() => { setSelection(new Set()); }, [model.content]);
  useEffect(() => { if (page !== currentPage) setPage(currentPage); }, [page, currentPage]);

  const changeDraft = (text: string): void => { setShowResults(false); model.invalidate(); batch.replaceIpText(text); };
  const switchMode = (next: 'import' | 'manage'): void => {
    if (mode === next || !leaveGuard.current()) return;
    model.invalidate(); setMode(next); setSelection(new Set());
    if (next === 'manage' && model.content === undefined) void model.read();
  };
  const copyToDraft = (): void => {
    if (model.content === undefined || (batch.ipText && !window.confirm('拷贝池快照会替换未提交的导入草稿，确认替换？'))) return;
    changeDraft(model.content); setSourcePool(poolKey); setMode('import');
  };
  const loadRemote = async (): Promise<void> => {
    if (remote.current || batch.checkingBatch || busy) return;
    if (!url.trim()) { model.message = '请输入远程 TXT URL'; render(value => value + 1); return; }
    if (batch.ipText && !window.confirm('远程加载会替换未提交的导入草稿，确认替换？')) return;
    model.invalidate(); const revision = model.revision;
    const controller = remote.current = new AbortController(); setRemoteBusy(true);
    try {
      const result = await client.remoteLoad(url.trim(), controller.signal);
      if (controller.signal.aborted || revision !== model.revision) return;
      changeDraft(result.content); setSourcePool(null);
      log(`[IP池] 远程导入 ${result.count} 条（尚未写入池）`);
    } catch (error) {
      if (!controller.signal.aborted) { model.message = errorMessage(error); log('[IP池] ' + model.message, 'error'); }
    } finally { if (remote.current === controller) { remote.current = null; setRemoteBusy(false); } }
  };
  const select = (key: string, checked: boolean): void => {
    if (model.reading) return;
    const next = new Set(selection); if (checked) next.add(key); else next.delete(key);
    setSelection(next); model.invalidate();
  };
  const selectedText = (): string => [...selection].flatMap(key => snapshot.entries.get(key)?.raw ?? []).join('\n');
  const download = (text: string): void => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = `${poolKey}.txt`; link.click(); URL.revokeObjectURL(url);
  };
  const runSideEffect = async (task: () => Promise<void>): Promise<void> => {
    if (sidePending.current || model.writing || containerBusy) return;
    sidePending.current = true; setSideBusy(true); model.invalidate(); model.message = '';
    try { await task(); refreshPools(); }
    catch (error) { model.message = '未取得成功确认：' + errorMessage(error) + '。可能已有部分操作完成，可重试。'; log('[IP池] ' + model.message, 'error'); }
    finally { sidePending.current = false; setSideBusy(false); }
  };
  const clean = (): void => {
    if (snapshot.entries.size > 200) { model.message = '洗库单次最多 200 个不同有效地址，当前池超出限制；未执行。'; render(value => value + 1); return; }
    if (!window.confirm(`确认洗库「${targetName}」？这会写回池内容，并将确定失效地址移入垃圾桶；有未知或无法识别项时整池跳过。`)) return;
    void runSideEffect(async () => {
      const result = await client.cleanPool(poolKey);
      model.message = result.skipped ? `洗库跳过：${result.unknown} 条未知或无法识别，未写回也未入桶`
        : `洗库完成：检测 ${result.checked}，保留 ${result.kept}，入桶 ${result.trashed}；请显式读取结果快照`;
      log('[IP池] ' + model.message, result.skipped ? 'warning' : 'success');
    });
  };
  const restore = (): void => {
    if (!selection.size) return;
    if (selection.size > MAX_POOL_RESTORE_ITEMS) { model.message = `单次最多恢复 ${MAX_POOL_RESTORE_ITEMS} 个地址，未执行。`; render(value => value + 1); return; }
    const addresses = [...selection];
    void runSideEffect(async () => {
      const result = await client.restoreTrash(addresses, { restoreToSource: true });
      model.message = `已恢复 ${result.restored} 条；${Object.entries(result.restoredByPool).map(([key, count]) => `${poolName(key)} ${count}`).join('，')}。请读取快照核对剩余条目`;
      setSelection(new Set()); log('[IP池] ' + model.message, 'success');
    });
  };
  const clearTrash = (): void => {
    if (!window.confirm('确认清空垃圾桶全部内容？这是写操作，不可撤销，与清空导入草稿无关。')) return;
    void runSideEffect(async () => { await client.clearTrash(); model.message = '垃圾桶清空请求已确认，请读取快照核对'; setSelection(new Set()); log('[IP池] ' + model.message, 'success'); });
  };
  const confirmPreview = async (): Promise<void> => {
    const plan = model.preview;
    if (!plan || (plan.mode === 'replace' && !plan.content.trim() && !window.confirm(`危险操作：确认清空「${targetName}」全部池内容？池容器仍保留。`))) return;
    if (await model.save()) { setEdit(null); setSelection(new Set()); log('[IP池] ' + model.message); refreshPools(); }
    else log('[IP池] ' + model.message, 'error');
  };

  return <section class="card p-4 dashboard-card dashboard-pool-card" aria-label="IP 库管理">
    <div class="dashboard-card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
      <h2 class="card-title m-0 fw-bold"><Icon name="database" /> IP库管理</h2>
      <div class="pool-tools">
        <select id="pool-selector" class="form-select form-select-sm" aria-label="选择 IP 池" value={poolKey}
          disabled={inputsLocked} onChange={event => {
            if (leaveGuard.current()) onPoolChange(event.currentTarget.value);
            else event.currentTarget.value = poolKey;
          }}>{poolOptions(pools, poolKey).map(pool => <option key={pool.key} value={pool.key}>{pool.name}</option>)}</select>
        <PoolActionMenu busy={inputsLocked} inTrash={inTrash} canDelete={NUMBERED_POOL_KEY_RE.test(poolKey)} actions={actions} />
      </div>
    </div>
    <ResourceFeedback state={pools} id="retry-pools" onRetry={refreshPools} />
    {!inTrash && <div class="pool-modes" role="group" aria-label="IP 池操作模式">
      {([['import', '导入与检测'], ['manage', '管理当前池']] as const).map(([value, label]) => <button type="button" class={mode === value ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-outline-secondary'} data-pool-mode={value}
        aria-pressed={mode === value} disabled={inputsLocked} onClick={() => switchMode(value)}>{label}</button>)}
    </div>}
    <p class="small text-secondary pool-summary">目标池：{targetName} · <span id="pool-count">{count ?? '—'}</span> 条{model.confirmed.has(poolKey) ? '（本次操作确认数量）' : '（读取快照）'}</p>
    {model.message && <p class="kv-alert compact pool-feedback" role="status">{model.message}</p>}
    {model.divergent !== undefined && <div class="kv-alert compact">
      <p>读取结果与本次确认值不同，可能尚未同步或已被其他操作修改。</p>
      <details><summary>查看不同的读取快照</summary><pre class="pool-text">{model.divergent || '（空池）'}</pre></details>
      <div class="pool-buttons"><button type="button" class="btn btn-sm btn-outline-secondary" disabled={busy} onClick={() => { model.divergent = undefined; render(value => value + 1); }}>保留本次确认显示</button>
        <button type="button" class="btn btn-sm btn-outline-primary" disabled={busy} onClick={() => { if (leaveGuard.current()) { model.adoptRead(); setSelection(new Set()); } }}>采用读取快照</button></div>
    </div>}
    {!inTrash && mode === 'import' ? <div class="ip-content-area pool-import">
      {sourcePool && <p class="small text-secondary">来源池：{poolName(sourcePool)} · 目标池：{targetName}</p>}
      <div class="pool-remote">
        <input id="remote-url" class="form-control form-control-sm" type="url" aria-label="远程 TXT URL" placeholder="远程 TXT URL" value={url} disabled={inputsLocked} onInput={event => setUrl(event.currentTarget.value)} onKeyDown={event => { if (event.key === 'Enter') void loadRemote(); }} />
        <button type="button" class="btn btn-sm btn-outline-primary" aria-label="从远程 URL 加载" disabled={inputsLocked} onClick={() => void loadRemote()}><Icon name="download" />{remoteBusy ? '加载中…' : '加载'}</button>
      </div>
      <details class="pool-remote-help small text-secondary"><summary>远程文本由服务端规范化</summary><p>无效原始行无法恢复；粘贴草稿保留原文并校验。</p></details>
      <div class="pool-view-header">
        <label class="small" for="ip-input" hidden={resultsVisible}>导入草稿（尚未保存）</label>
        <span class="small" hidden={!resultsVisible}>检测结果（原文保留）</span>
        <div class="pool-view-switch" role="group" aria-label="导入内容视图">
          <button type="button" class="btn btn-sm btn-outline-secondary" data-action="view-draft" aria-pressed={!resultsVisible} onClick={() => setShowResults(false)}>草稿</button>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-action="view-results" aria-pressed={resultsVisible} disabled={!report} onClick={() => setShowResults(true)}>结果</button>
        </div>
      </div>
      <div class="pool-data-body">
      <textarea id="ip-input" class="form-control ip-input" rows={6} hidden={resultsVisible} value={batch.ipText} readOnly={inputsLocked} aria-busy={batch.checkingBatch} onInput={event => changeDraft(event.currentTarget.value)} placeholder="IPv4、[IPv6]:port、域名及已有元数据和备注" />
      {report && <div class="pool-report" hidden={!resultsVisible} role="region" aria-label="本次检测结果">
        <div class="pool-buttons" role="group" aria-label="检测结果分类">
          {(['alive', 'dead', 'unknown', 'invalid', 'incomplete'] as const).map(value => {
            const count = value === 'invalid' ? report.invalid.length : value === 'incomplete' ? report.incomplete.length : report.items.filter(item => item.status === value).length;
            const label = { alive: '可用', dead: '失效', unknown: '未知', invalid: '格式无效', incomplete: '未完成' }[value];
            return <button type="button" class="btn btn-sm btn-outline-secondary" aria-pressed={category === value} onClick={() => setCategory(value)}>{label} {count}</button>;
          })}
        </div>
        {batch.checkingBatch && <p class="small text-secondary">检测中，请等待或先停止再预览。</p>}
        <ul class="pool-result-list" tabIndex={0} aria-label="检测结果列表">{category === 'invalid' || category === 'incomplete' ? report[category].map((line, index) => <li key={index}><code>{line}</code></li>)
          : report.items.filter(item => item.status === category).map((item, index) => <li key={index}>
            <strong>{item.address} · {probeStatusLabel(item.status, item.code)}</strong>
            <span>{[item.exitIp, item.asn, item.country, item.exitFamily, item.latencyMs === undefined ? '' : `${item.latencyMs}ms`].filter(Boolean).join(' · ')}</span>
            {shouldLogProbe(item) && <span class="pool-diagnostic">{formatProbeLog(item)}</span>}
          </li>)}</ul>
        <div class="pool-buttons">
          {report.items.some(item => item.status === 'unknown') && <button type="button" class="btn btn-sm btn-outline-secondary" disabled={batch.checkingBatch || busy} onClick={() => batch.handleCheckBatch()}>重新检测草稿</button>}
          <button type="button" class="btn btn-sm btn-outline-secondary" onClick={() => download(report.text)}>导出检测文本</button>
        </div>
      </div>}
      </div>
      {!resultsVisible && invalid.length > 0 && <details class="kv-alert compact pool-invalid"><summary>格式无效 {invalid.length} 条，请修正后直接追加</summary><pre class="pool-text">{invalid.join('\n')}</pre></details>}
      {!probeConfigured && <p class="kv-alert compact">尚未配置主复检或备用复检接口，检测将报告探针异常。</p>}
      <div class="pool-buttons" id="main-actions">
        <button type="button" class={batch.checkingBatch ? 'btn btn-danger' : 'btn btn-primary'} aria-label={batch.checkingBatch ? '停止批量检测' : '批量检测导入草稿'} disabled={!batch.checkingBatch && (!configReady || busy || remoteBusy)} onClick={() => { model.invalidate(); if (batch.checkingBatch) batch.handleStopBatch(); else batch.handleCheckBatch(); }}><Icon name={batch.checkingBatch ? 'stop' : 'activity'} />{batch.checkingBatch ? '停止检测' : '检测'}</button>
        <button type="button" class="btn btn-success" data-action="append-alive" disabled={inputsLocked || model.previewing || !report?.items.some(item => item.status === 'alive')} onClick={() => void model.prepare(report!.items.filter(item => item.status === 'alive').map(item => item.line).join('\n'), 'append')}><Icon name="plus" />预览追加可用</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-action="append-input" disabled={inputsLocked || model.previewing || !batch.ipText.trim() || !!invalid.length} onClick={() => void model.prepare(batch.ipText, 'append')}>直接追加输入地址</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" disabled={inputsLocked} onClick={() => { changeDraft(''); setSourcePool(null); }}>清空输入</button>
      </div>
    </div> : <div class="ip-content-area pool-management">
      {inTrash && <p class="small text-secondary">垃圾桶仅支持选择恢复或清空；恢复到来源池，来源缺失由服务端回退。</p>}
      <div class="pool-buttons">
        <button type="button" class="btn btn-sm btn-outline-primary" data-action="read-pool" disabled={model.reading || busy} onClick={() => { setSelection(new Set()); void model.read(); }}><Icon name="folder" />{model.reading ? '读取中…' : '读取池快照'}</button>
        {!inTrash && <button type="button" class="btn btn-sm btn-outline-secondary" disabled={model.content === undefined || managementLocked || !!edit} onClick={copyToDraft}>拷贝到导入区</button>}
        <button type="button" class="btn btn-sm btn-outline-secondary" disabled={model.content === undefined} onClick={() => download(selection.size ? selectedText() : model.content!)}>导出{selection.size ? '选择' : '完整池'}</button>
      </div>
      {model.content !== undefined && (edit ? <>
        <label class="small" for="pool-editor">完整编辑「{targetName}」（覆盖整个文本及独立备注）</label>
        <textarea id="pool-editor" class="form-control ip-input" rows={8} value={edit.text} readOnly={busy} onInput={event => { setEdit({ ...edit, text: event.currentTarget.value }); model.invalidate(); }} />
        {invalidPoolLines(edit.text).length > 0 && <pre class="pool-text kv-alert">无法识别：{invalidPoolLines(edit.text).join('\n')}</pre>}
        <div class="pool-buttons"><button type="button" class="btn btn-success" data-action="replace-pool" disabled={busy || model.previewing || !!invalidPoolLines(edit.text).length} onClick={() => void model.prepare(edit.text, 'replace')}>预览覆盖</button>
          <button type="button" class="btn btn-outline-secondary" disabled={busy} onClick={() => { if (leaveGuard.current()) model.invalidate(); }}>取消完整编辑</button></div>
      </> : <>
        <label class="small" for="universal-filter">视图筛选（不改池内容；更改即清空选择）</label>
        <input id="universal-filter" class="form-control form-control-sm" value={filter} placeholder="country:US asn:AS64500 | stack:dual" disabled={busy} onInput={event => {
          setFilter(event.currentTarget.value); setSelection(new Set()); setPage(0); model.invalidate();
          model.message = '筛选已变化，选择已清空';
        }} />
        {invalidFilter && <p class="kv-alert compact">筛选条件无效，请检查端口、空条件或 OR 分支。</p>}
        <p class="small text-secondary" id="filter-preview">匹配 {rows.length} / {snapshot.entries.size} 条 · 已选择 {selection.size} 条 · 库条目未检测</p>
        <div class="pool-table-wrap table-responsive">
          <table class="table table-sm pool-table" aria-label={inTrash ? '垃圾桶条目' : '当前池读取快照'}>
            <thead><tr><th scope="col">选择</th><th scope="col">地址 / 元数据</th><th scope="col">{inTrash ? '来源池' : '检测状态'}</th></tr></thead>
            <tbody>{shown.map(([key, item]) => <tr key={key}>
              <td><input type="checkbox" aria-label={`选择 ${key}`} checked={selection.has(key)} disabled={managementLocked} onChange={event => select(key, event.currentTarget.checked)} /></td>
              <td><strong>{item.entry.address}</strong><small>{[item.entry.asn, item.entry.country, item.entry.stack, item.entry.comment].filter(Boolean).join(' · ')}</small></td>
              <td>{inTrash ? poolName(sourcePoolFromTrash(item.raw) ?? 'ip_pool_default') : '未检测'}</td>
            </tr>)}</tbody></table>
        </div>
        {pages > 1 && <div class="pool-buttons"><button type="button" class="btn btn-sm btn-outline-secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>前一页</button><span>{currentPage + 1} / {pages}</span><button type="button" class="btn btn-sm btn-outline-secondary" disabled={currentPage + 1 >= pages} onClick={() => setPage(currentPage + 1)}>后一页</button></div>}
        {snapshot.invalid.length > 0 && <details><summary>独立备注 / 无法识别内容（{snapshot.invalid.length}）</summary><pre class="pool-text">{snapshot.invalid.join('\n')}</pre></details>}
        <div class="pool-buttons">
          <button type="button" class="btn btn-sm btn-outline-secondary" disabled={managementLocked || invalidFilter} onClick={() => { setSelection(new Set(rows.map(([key]) => key))); model.invalidate(); }}>选择当前筛选结果</button>
          {inTrash ? <>
            <button type="button" class="btn btn-success" data-action="restore-trash" disabled={managementLocked || !selection.size} onClick={restore}><Icon name="recycle" />恢复选中</button>
            <button type="button" class="btn btn-sm btn-outline-danger" onClick={clearTrash} disabled={managementLocked}>清空垃圾桶</button>
          </> : <>
            <button type="button" class="btn btn-sm btn-outline-danger" data-action="remove-selected" disabled={managementLocked || !selection.size || model.previewing} onClick={() => void model.prepare(selectedText(), 'remove')}>预览删除选择</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" disabled={managementLocked} onClick={() => { model.invalidate(); setEdit({ poolKey, original: model.content!, text: model.content! }); }}>完整编辑</button>
            <button type="button" class="btn btn-sm btn-outline-danger" disabled={managementLocked || !snapshot.entries.size} onClick={clean}>洗库（写库与入桶）</button>
          </>}
        </div>
      </>)}
    </div>}
    {model.previewing && <p role="status" class="small text-secondary">正在读取变更预览…</p>}
    {model.preview && <Modal id="pool-preview-title" title={`变更预览 · ${targetName}`} className="pool-preview-modal" onClose={() => { if (!model.writing) model.invalidate(); }}>
      <p>操作：{({ append: '追加', replace: '覆盖', remove: '删除选择' })[model.preview.mode]}</p>
      <p>地址 {model.preview.data.currentCount} → {model.preview.data.count} · 新增 {model.preview.data.added} / 更新 {model.preview.data.updated} / 移除 {model.preview.data.removed}</p>
      <p>无法识别行 {model.preview.data.unrecognized.before} → {model.preview.data.unrecognized.after} · 独立备注 {model.preview.data.standaloneComments.before} → {model.preview.data.standaloneComments.after}</p>
      <p class="small text-secondary">预览基于读取快照，不会检测或加锁。{({ replace: '覆盖替换整个文本，独立备注也可能改变；下方是逐地址差异。', append: '追加不会清理原池中的失效地址。', remove: '仅删除明确选择的地址，不自动移入垃圾桶。' })[model.preview.mode]}</p>
      {!model.preview.data.changed ? <p>本次读取快照无变化，未执行新写入。</p> : !model.preview.data.changes.length && <p>地址差异为零，但文本规范化或备注发生变化。</p>}
      <details open><summary>全部地址差异（{model.preview.data.changes.length}）</summary><ul class="pool-change-list">{model.preview.data.changes.map((change, index) => <li key={index}>
        <strong>{change.kind} · {change.address}</strong>{change.before !== undefined && <pre class="pool-text">之前：{change.before}</pre>}{change.after !== undefined && <pre class="pool-text">之后：{change.after}</pre>}
      </li>)}</ul></details>
      {model.message && <p role="status" class="kv-alert compact">{model.message}</p>}
      <div class="custom-modal-buttons">
        <button type="button" class="btn btn-outline-secondary" disabled={model.writing} onClick={() => model.invalidate()}>关闭预览</button>
        <button type="button" class="btn btn-success" data-action="confirm-pool" disabled={model.writing || !model.preview.data.changed} onClick={() => void confirmPreview()}>{model.writing ? '正在等待确认…' : `确认${({ append: '追加到', replace: '覆盖', remove: '删除于' })[model.preview.mode]}「${targetName}」`}</button>
      </div>
    </Modal>}
  </section>;
}

export interface PoolContainerActions {
  readonly createPool: () => void;
  readonly renamePool: () => void;
  readonly openPoolOrder: () => void;
  readonly deletePool: () => void;
}

function PoolActionMenu({
  busy,
  inTrash,
  canDelete,
  actions,
}: {
  readonly busy: boolean;
  readonly inTrash: boolean;
  readonly canDelete: boolean;
  readonly actions: PoolContainerActions;
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

  const run = (action: () => void): void => {
    setOpen(false);
    action();
  };

  // 元组：图标、文案、禁用、危险、动作。
  const items: readonly (readonly [IconName, string, boolean, boolean, () => void])[] = [
    ['plus', '新建池', false, false, actions.createPool],
    ['pencil', '重命名当前池', inTrash, false, actions.renamePool],
    ['sort', '自定义池排序', false, false, actions.openPoolOrder],
    ['trash', '删除当前池', !canDelete, true, actions.deletePool],
  ];

  return (
    <div class="action-menu" ref={container}>
      <button
        id="pool-action-trigger"
        class="btn btn-sm btn-outline-secondary action-menu-trigger"
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <span><Icon name="database" /> 池操作</span> <span class="action-menu-caret">▾</span>
      </button>
      {open && (
        <div class="action-menu-panel" role="menu" aria-label="池操作">
          {items.map(([icon, label, disabled, danger, action]) => (
            <button
              key={label}
              class={`action-menu-item${danger ? ' danger' : ''}`}
              type="button"
              role="menuitem"
              disabled={busy || disabled}
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
