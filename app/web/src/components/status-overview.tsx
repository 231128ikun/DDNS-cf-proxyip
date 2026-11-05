import { useId, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import type { CheckTargetItemResponse, CheckTargetResponse, ProbeResponse } from '../../../src/contracts/probe';
import { formatPoolEntry, parsePoolEntry, updatePoolEntryFromProbe } from '../../../src/domain/pool-entry';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
import type { RequestState } from '../state/request-state';
import { currentStatusRows, type TargetStatusView } from '../state/target-status';
import { Icon } from './icon';
import { AddressText } from './address-text';
import { probeStatusLabel } from './probe-status';
import { TargetSelector, type TargetSelectorProps } from './target-selector';

interface StatusOverviewProps extends Pick<TargetSelectorProps, 'bindings' | 'targetChoices' | 'onSelectTarget'> {
  readonly check: RequestState<CheckTargetResponse>;
  readonly current: RequestState<TargetStatusView>;
  readonly selectedKey: string | null;
  readonly targetPort: number | 'any';
  readonly lookup: string;
  readonly onLookupChange: (value: string) => void;
  readonly onLookup: (event: Event) => void;
  readonly onRefresh: () => void;
  readonly onCopy: (address: string) => void;
  readonly onCopyAddress: (address: string) => void;
  readonly onAdd: (value: string) => Promise<boolean>;
  readonly onDelete: (id: string, address?: string) => void;
}

/** 当前 DNS 与任意目标探测共用一个展示区域，刷新或切换目标后回到当前记录。 */
export function StatusOverview({ check, current, selectedKey, targetPort, lookup, onLookupChange,
  onLookup, onRefresh, onCopy, onCopyAddress, onAdd, onDelete, bindings, targetChoices, onSelectTarget }: StatusOverviewProps) {
  const [addValue, setAddValue] = useState('');
  const [adding, setAdding] = useState(false);
  return (
    <section class="card p-4 probe-overview-card" aria-labelledby="status-overview-title">
      <div class="status-overview-toolbar mb-3">
        <div class="status-overview-context">
          <h2 id="status-overview-title" class="card-title m-0 fw-bold"><Icon name="antenna" /> 解析实况</h2>
          <div class="status-target-controls">
            <TargetSelector bindings={bindings} selectedTargetKey={selectedKey} targetPort={targetPort} targetChoices={targetChoices} onSelectTarget={onSelectTarget} />
            <button class="btn btn-outline-secondary btn-sm" type="button" onClick={onRefresh} aria-label="刷新当前 DNS 记录" title="刷新当前 DNS 记录">
              <Icon name="refresh" />
            </button>
          </div>
        </div>
        <form class="d-flex gap-2 align-items-center flex-grow-1 ddns-lookup-form" onSubmit={onLookup}>
          <input id="lookup-domain" type="text" class="form-control form-control-sm"
            placeholder="探测: 域名 / IP:端口 / txt@域名" aria-label="要探测的域名或 IP"
            value={lookup} onInput={(event) => onLookupChange(event.currentTarget.value)} autocomplete="off" spellcheck={false} />
          <button class="btn btn-primary btn-sm" type="submit" disabled={check.status === 'loading'} aria-label={check.status === 'loading' ? '探测中…' : '探测'} title="探测">
            <Icon name="search" /> {check.status === 'loading' ? '探测中…' : '探测'}
          </button>
        </form>
      </div>
      {selectedKey && <form id="manual-add-section" class="input-group input-group-sm mb-2" onSubmit={async (event) => {
        event.preventDefault();
        if (adding || !addValue.trim()) return;
        const submitted = addValue;
        setAdding(true);
        try {
          if (await onAdd(submitted)) setAddValue((current) => current === submitted ? '' : current);
        } finally { setAdding(false); }
      }}>
        <input id="manual-add-ip" type="text" class="form-control" aria-label="手动添加 IP"
          placeholder="手动添加IP到当前域名 (如: 1.2.3.4:443)" value={addValue}
          onInput={(event) => setAddValue(event.currentTarget.value)} />
        <button class="btn btn-success" type="submit" disabled={adding || !selectedKey} aria-label={adding ? '添加中…' : '添加'} title="添加"><Icon name="plus" /></button>
      </form>}
      <div id="status-display" class="status-display">
        <table class="table text-center status-table" role="table" aria-label="解析与探测结果">
          <thead class="status-table-head" role="rowgroup"><tr role="row">
            <th scope="col">目标地址</th><th scope="col">Colo</th><th scope="col">延迟</th><th scope="col">状态</th><th scope="col">出口 IP / 线路</th><th scope="col">操作</th>
          </tr></thead>
          <tbody id="status-table" role="rowgroup">
            {check.status === 'idle'
              ? <CurrentRows state={current} selectedKey={selectedKey} port={targetPort} onCopyAddress={onCopyAddress} onDelete={onDelete} />
              : <LookupRows state={check} onCopy={onCopy} onCopyAddress={onCopyAddress} />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function LookupRows({ state, onCopy, onCopyAddress }: { readonly state: RequestState<CheckTargetResponse>;
  readonly onCopy: (address: string) => void; readonly onCopyAddress: (address: string) => void }) {
  if (state.status === 'loading') return <EmptyRow text="正在检测…" />;
  if (state.status === 'error') return <EmptyRow text={state.message} error />;
  if (state.status !== 'ready' || state.data.items.length === 0) return <EmptyRow text="暂无记录" />;
  return <>{state.data.items.map((item) => <ProbeRow key={item.address} item={item} onCopy={onCopy} onCopyAddress={onCopyAddress} />)}</>;
}

function ProbeRow({ item, onCopy, onCopyAddress }: { readonly item: CheckTargetItemResponse;
  readonly onCopy: (address: string) => void; readonly onCopyAddress: (address: string) => void }) {
  const result = item.result;
  return <StatusRow address={item.address} result={result} onCopyAddress={onCopyAddress}
    action={<button class="btn btn-sm btn-outline-primary status-action" type="button" onClick={() => onCopy(probeInputLine(item))} aria-label={`加入输入：${item.address}`}><Icon name="plus" /> 加入输入</button>} />;
}

function CurrentRows({ state, selectedKey, port, onCopyAddress, onDelete }: {
  readonly state: RequestState<TargetStatusView>;
  readonly selectedKey: string | null;
  readonly port: number | 'any';
  readonly onCopyAddress: (address: string) => void;
  readonly onDelete: (id: string, address?: string) => void;
}) {
  if (!selectedKey) return <EmptyRow text="请先到配置中心添加管理域名" />;
  if (state.status === 'loading' || state.status === 'idle') return <EmptyRow text="正在读取当前 DNS 记录…" />;
  if (state.status === 'error') return <EmptyRow text={state.message} error />;
  const rows = currentStatusRows(state.data, port);
  const probes = new Map(state.data.probes.map((item) => [item.address, item]));
  if (!rows.length) return <EmptyRow text="暂无记录" />;
  return <>{rows.map(({ record, address }) => {
    const probe = probes.get(address);
    return <StatusRow key={`${record.id}:${address}`} address={address} onCopyAddress={onCopyAddress}
      result={probe ? { ...probe, exits: probe.exits ?? [] } : undefined}
      action={<button class="btn btn-sm btn-outline-danger status-action" type="button" onClick={() => onDelete(record.id, record.type === 'TXT' ? address : undefined)} aria-label={`删除 ${address}`}>删除</button>} />;
  })}</>;
}

function StatusRow({ address, result, onCopyAddress, action }: {
  readonly address: string;
  readonly result: ProbeResponse | undefined;
  readonly onCopyAddress: (address: string) => void;
  readonly action: ComponentChildren;
}) {
  const [expanded, setExpanded] = useState(false);
  const detailId = useId();
  const hasExit = Boolean(result && (result.exits.length || result.exitIp));
  const exitLabel = expanded ? '收起出口' : '出口详情';
  return <tr class="status-row" role="row">
    <td role="cell" class="status-address"><AddressPill address={address} onCopy={onCopyAddress} /></td>
    <td role="cell"><span class="colo-badge">{result?.colo ?? '-'}</span></td>
    <td role="cell"><span class="latency-badge">{result?.latencyMs === undefined ? '—' : `${result.latencyMs}ms`}</span></td>
    <td role="cell" class="status-decision">
      <span class={`status-badge ${result?.status === 'alive' ? 'ok' : result?.status === 'dead' ? 'bad' : 'warn'}`} title={result?.message ?? result?.code}>{result ? probeStatusLabel(result.status, result.code) : '未检测'}</span>
      {hasExit && <button type="button" class="btn btn-sm btn-outline-secondary status-exit-toggle"
        aria-label={`${exitLabel}：${address}`} aria-expanded={expanded} aria-controls={detailId}
        onClick={() => setExpanded(value => !value)}>{exitLabel}</button>}
      {result && result.status !== 'alive' && (result.message || result.code) && <small class="status-reason">{result.message ?? result.code}</small>}
    </td>
    <td id={detailId} role="cell" class={expanded ? 'status-exit-cell' : 'status-exit-cell is-collapsed'}>
      {result ? <ProbeExits result={result} onCopy={onCopyAddress} /> : '—'}
    </td>
    <td role="cell" class="status-row-action">{action}</td>
  </tr>;
}

function EmptyRow({ text, error = false }: { readonly text: string; readonly error?: boolean }) {
  return <tr><td colspan={6} class={`${error ? 'text-danger' : 'text-secondary'} p-4`}>{text}</td></tr>;
}

function AddressPill({ address, onCopy }: { readonly address: string; readonly onCopy: (address: string) => void }) {
  return <button class="address-pill" type="button" title="点击复制" aria-label={`复制维护地址 ${address}`} onClick={() => onCopy(address)}><AddressText value={address} /></button>;
}

function ProbeExits({ result, onCopy }: { readonly result: ProbeResponse; readonly onCopy: (value: string) => void }) {
  if (result.exits.length === 0) return <>{result.exitIp ?? '-'}</>;
  return <>{result.exits.map((exit, index) => {
    const asn = exit.asn ? `AS${exit.asn.replace(/^AS/i, '')}` : '';
    const network = [asn, exit.organization].filter(Boolean).join(' · ');
    return <div class="exit-detail" key={index}>
      <span class="exit-tag exit-stack">{exit.family === 'unknown' ? 'EXIT' : exit.family.toUpperCase()}</span>
      <button type="button" class="exit-ip" disabled={!exit.ip} title="点击复制出口 IP" aria-label={`复制出口 IP ${exit.ip ?? '未知'}`} onClick={() => exit.ip && onCopy(exit.ip)}><AddressText value={exit.ip ?? '—'} /></button>
      <span class="exit-tag" title={[exit.country, exit.region, exit.city].filter(Boolean).join(' · ')}>{[exit.country, exit.city || exit.region].filter(Boolean).join(' · ') || '-'}</span>
      <span class="exit-tag" title={network}>{asn && <code class="syntax-meta">{asn}</code>}{asn && exit.organization && ' · '}{exit.organization || (!asn && '—')}</span>
    </div>;
  })}</>;
}

function probeInputLine(item: CheckTargetItemResponse): string {
  const entry = parsePoolEntry(item.address);
  const target = parseProxyTarget(item.address, 443);
  if (!entry || !target) return item.address;
  return formatPoolEntry(updatePoolEntryFromProbe(entry, { ...item.result, target }));
}
