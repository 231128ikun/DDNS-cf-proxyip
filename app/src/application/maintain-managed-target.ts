import { readPoolSnapshot } from '../domain/pool-snapshot';
import { parseRuntimeSetting } from '../contracts/runtime-settings';
import type { MaintenanceCandidateStats, MaintenanceDnsState, MaintenanceLogLine } from '../contracts/maintenance';
import { dnsRecordTypeForHost, formatProxyAuthority, parseProxyTarget } from '../domain/proxy-target';
import { parseTxtAddresses } from '../domain/txt-record';
import { activeValueForEntry, probeMatchesTarget, selectCandidateEntries, type ManagedTarget } from '../domain/managed-target';
import { buildMaintenancePlan, countActiveCurrent, decideCurrentResult, orderCandidatesForAddition,
  type CandidateMaintenanceItem, type CurrentMaintenanceItem, type MaintenancePlan } from '../domain/maintenance';
import { canonicalAddressKey, type PoolEntry } from '../domain/pool-entry';
import { mapWithConcurrency } from '../util/concurrency';
import { isProbeErrorResult, unknown, type ProbeResult } from '../domain/probe-result';
import type { DnsRecord, DnsRepository, DnsZone } from '../ports/dns-repository';
import type { PoolRepository } from '../ports/pool-repository';
import type { ProbeAdapter } from '../ports/probe';

export interface MaintainManagedTargetCommand {
  readonly target: ManagedTarget;
  readonly zone: DnsZone;
  readonly poolKey: string;
  readonly signal?: AbortSignal;
}

const CANDIDATE_EXPLORE_FACTOR = 2;
const CANDIDATE_EXPLORE_EXTRA = 1;
/** 为 DNS 与通知保留子请求余量，不把整池扫描当作无界任务。 */
const MAX_CANDIDATE_PROBES = 12;

export interface MaintainManagedTargetDependencies {
  readonly probe: ProbeAdapter;
  readonly pools: PoolRepository;
  readonly dns: DnsRepository;
  readonly concurrency?: number;
}

export interface MaintenanceReport {
  readonly target: ManagedTarget;
  readonly poolKey: string;
  readonly plan: MaintenancePlan;
  readonly deleted: number;
  readonly added: number;
  readonly dnsUpdated: boolean;
  readonly probeErrors: number;
  readonly errors: readonly string[];
  readonly dns?: MaintenanceDnsState;
  readonly activeCount?: number;
  readonly candidates?: MaintenanceCandidateStats;
  readonly candidateResults?: readonly CandidateMaintenanceItem[];
  readonly archived?: number;
}

export class MaintainManagedTarget {
  private readonly concurrency: number;

  constructor(private readonly dependencies: MaintainManagedTargetDependencies) {
    this.concurrency = parseRuntimeSetting('CONCURRENT_CHECKS', dependencies.concurrency);
  }

  async execute(command: MaintainManagedTargetCommand, onProgress?: (line: MaintenanceLogLine) => void): Promise<MaintenanceReport> {
    const progress = onProgress && ((message: string) => onProgress({ message: command.target.domain + ' ('
      + (command.target.mode === 'A' ? 'A/AAAA' : 'TXT') + ') · ' + message, tone: 'info' }));
    progress?.('读取库存和 DNS');
    const [poolText, currentItems] = await Promise.all([
      this.dependencies.pools.load(command.poolKey),
      this.loadCurrentRecords(command),
    ]);
    command.signal?.throwIfAborted();
    const current = await this.probeCurrentRecords(currentItems, command.target, progress, command.signal);
    command.signal?.throwIfAborted();
    const currentDecisions = current.map(item => ({ item, decision: decideCurrentResult(item.result, command.target) }));
    // 探针自身已经复检；同一轮补货不再重复探测当前 DNS 地址。
    const excluded = new Set(current.map(item => canonicalAddressKey(item.address)));
    const entries = parsePoolEntries(poolText);
    const candidates = selectCandidateEntries(entries, command.target, excluded);
    const inspected = await this.probeCandidates(command.target, candidates, countActiveCurrent(currentDecisions), progress, command.signal);
    command.signal?.throwIfAborted();
    const plan = buildMaintenancePlan({ target: command.target, current, candidates: inspected.items, poolText,
      ...(inspected.stats.remaining > 0 && (inspected.stats.checked >= MAX_CANDIDATE_PROBES || inspected.items.some(incompleteProbe))
        ? { rotateCandidates: inspected.items.filter(item => item.result.status === 'unknown' && !incompleteProbe(item)).map(item => item.entry.address) } : {}),
    });
    const probeErrors = new Set(current.filter(item => isProbeErrorResult(item.result)).map(item => canonicalAddressKey(item.address))).size
      + inspected.items.filter(item => isProbeErrorResult(item.result)).length;
    const errors: string[] = [];
    let trashSaved = plan.trash.length === 0;
    if (!trashSaved || plan.poolChanged || plan.additions.length
      || plan.current.some(item => item.decision === 'remove-dead' || item.decision === 'remove-mismatch')) {
      progress?.('核对并应用维护结果');
    }
    if (plan.trash.length) {
      command.signal?.throwIfAborted();
      try {
        await this.dependencies.pools.addToTrash(plan.trash.map(item => ({ ...item, poolKey: command.poolKey })));
        trashSaved = true;
      } catch { errors.push('写入垃圾桶失败'); }
    }
    // 归档失败禁止移除来源，但仍可安全补充新的可用地址。
    const dnsResult = await this.applyDnsChanges(command, plan, errors, trashSaved);
    if (plan.poolChanged && trashSaved) {
      command.signal?.throwIfAborted();
      try { await this.dependencies.pools.save(command.poolKey, plan.nextPoolText); }
      catch { errors.push('保存 IP 池失败'); }
    }
    const knownActive = new Set(currentDecisions.filter(item => item.decision === 'active').map(item => item.item.value));
    for (const value of dnsResult.dns.added) knownActive.add(value);
    return { target: command.target, poolKey: command.poolKey, plan, deleted: dnsResult.deleted, added: dnsResult.added,
      dnsUpdated: dnsResult.updated, probeErrors, errors, dns: dnsResult.dns,
      activeCount: dnsResult.dns.after.filter(value => knownActive.has(value)).length,
      candidates: { ...inspected.stats, sourceCount: entries.length }, candidateResults: inspected.items, archived: trashSaved ? plan.trash.length : 0,
    };
  }

  private async loadCurrentRecords(command: MaintainManagedTargetCommand): Promise<CurrentMaintenanceItem[]> {
    if (command.target.mode === 'A') {
      const records = await this.dependencies.dns.listAddressRecords(command.zone, command.target.domain);
      return records.map(record => currentItemFromAddressRecord(record, command.target)).filter(isPresent);
    }
    const [record] = await this.dependencies.dns.listTxtRecords(command.zone, command.target.domain);
    return record ? parseTxtAddresses(record.content).map(address => currentItemFromTxtAddress(record, address, command.target)).filter(isPresent) : [];
  }

  private async probeCurrentRecords(items: readonly CurrentMaintenanceItem[], target: ManagedTarget, progress?: (message: string) => void, signal?: AbortSignal): Promise<CurrentMaintenanceItem[]> {
    const unique = new Map<string, CurrentMaintenanceItem>();
    for (const item of items) if (item.result.code !== 'INVALID_DNS_VALUE') unique.set(canonicalAddressKey(item.address), item);
    if (unique.size) progress?.('开始检测当前解析 · ' + unique.size + ' 个地址');
    let settled = 0;
    const checked = await mapWithConcurrency([...unique], this.concurrency, async ([key, item]) => {
      const result = await probeSafely(this.dependencies.probe, item, target, signal);
      settled++;
      if (settled === 1 || settled % 4 === 0 || settled === unique.size) progress?.('当前解析已返回 ' + settled + '/' + unique.size);
      return [key, result] as const;
    });
    const results = new Map(checked);
    return items.map(item => item.result.code === 'INVALID_DNS_VALUE' ? item : ({ ...item, result: results.get(canonicalAddressKey(item.address))! }));
  }

  /** 缺额未满足时继续后续窗口；异常候选不使补货提前退出。 */
  private async probeCandidates(target: ManagedTarget, candidates: readonly PoolEntry[], active: number, progress?: (message: string) => void, signal?: AbortSignal): Promise<{
    items: readonly CandidateMaintenanceItem[]; stats: MaintenanceCandidateStats;
  }> {
    const needed = Math.max(0, target.minActive - active);
    const items: CandidateMaintenanceItem[] = [];
    const matched = new Set<string>();
    let checked = 0;
    const limit = Math.min(candidates.length, MAX_CANDIDATE_PROBES);
    if (needed && limit) progress?.('开始检测补货候选 · 本目标最多 ' + limit + ' 个');
    while (needed > matched.size && checked < limit) {
      signal?.throwIfAborted();
      const missing = needed - matched.size;
      const size = Math.min(limit - checked, missing * CANDIDATE_EXPLORE_FACTOR + CANDIDATE_EXPLORE_EXTRA);
      const batch = await mapWithConcurrency(candidates.slice(checked, checked + size), this.concurrency, async entry => {
        const parsed = parseProxyTarget(entry.address, target.port ?? 443)!;
        const address = target.mode === 'A' && target.port ? formatProxyAuthority(parsed.host, target.port) : parsed.authority;
        const item = { entry, address, value: activeValueForEntry(entry, target) };
        const inspected = { ...item, result: await probeSafely(this.dependencies.probe, item, target, signal) };
        if (!incompleteProbe(inspected)) {
          checked++;
          progress?.('候选已检测 ' + checked + ' 个');
        }
        return inspected;
      });
      items.push(...batch);
      for (const item of batch) if (probeMatchesTarget(item.result, target)) matched.add(item.value);
      if (batch.some(incompleteProbe)) break;
    }
    return { items: orderCandidatesForAddition(items, target), stats: { total: candidates.length, checked,
      unknown: items.filter(item => item.result.status === 'unknown' && !incompleteProbe(item)).length, remaining: candidates.length - checked } };
  }

  private async applyDnsChanges(command: MaintainManagedTargetCommand, plan: MaintenancePlan, errors: string[], allowRemoval: boolean): Promise<{
    deleted: number; added: number; updated: boolean; dns: MaintenanceDnsState;
  }> {
    command.signal?.throwIfAborted();
    const before = uniqueValues(plan.current.map(item => item.item.value));
    const state = (after: readonly string[]): MaintenanceDnsState => ({ before, after: uniqueValues(after),
      added: uniqueValues(after).filter(value => !before.includes(value)), removed: before.filter(value => !after.includes(value)) });
    if (command.target.mode === 'A') {
      const records = new Map(plan.current.map(({ item }) => [item.recordId!, item.value]));
      let deleted = 0;
      let added = 0;
      if (allowRemoval) for (const { item, decision } of plan.current) {
        if ((decision !== 'remove-dead' && decision !== 'remove-mismatch') || !item.recordId) continue;
        command.signal?.throwIfAborted();
        try { await this.dependencies.dns.deleteRecord(command.zone, item.recordId); records.delete(item.recordId); deleted++; }
        catch { errors.push('删除 DNS 记录失败: ' + item.value); }
      }
      for (const candidate of plan.additions) {
        if ([...records.values()].includes(candidate.value)) continue;
        command.signal?.throwIfAborted();
        try {
          const record = await this.dependencies.dns.addAddressRecord(command.zone, command.target.domain, candidate.value, dnsRecordTypeForHost(candidate.value));
          records.set(record.id, candidate.value);
          added++;
        } catch { errors.push('添加 DNS 记录失败: ' + candidate.value); }
      }
      const dns = state([...records.values()]);
      return { deleted, added, updated: dns.added.length > 0 || dns.removed.length > 0, dns };
    }
    const after = allowRemoval ? plan.dnsValues : uniqueValues([...before, ...plan.additions.map(item => item.value)]);
    if (sameValues(before, after)) return { deleted: 0, added: 0, updated: false, dns: state(before) };
    try {
      const recordId = plan.current.find(item => item.item.recordId)?.item.recordId ?? null;
      if (!after.length) {
        if (recordId) await this.dependencies.dns.deleteRecord(command.zone, recordId);
        return { deleted: recordId ? 1 : 0, added: 0, updated: Boolean(recordId), dns: state([]) };
      }
      await this.dependencies.dns.upsertTxtRecord(command.zone, command.target.domain, recordId, after);
      return { deleted: 0, added: 0, updated: true, dns: state(after) };
    } catch {
      errors.push('更新 TXT 记录失败');
      return { deleted: 0, added: 0, updated: false, dns: state(before) };
    }
  }
}

function currentItemFromAddressRecord(record: DnsRecord, target: ManagedTarget): CurrentMaintenanceItem | null {
  const parsed = parseProxyTarget(record.content, target.port ?? 443);
  const expectedFamily = record.type === 'AAAA' ? 'ipv6' : 'ipv4';
  if (!parsed || parsed.family !== expectedFamily) return invalidDnsItem(record, record.content);
  return { recordId: record.id, address: target.port ? formatProxyAuthority(parsed.host, target.port) : parsed.authority,
    value: parsed.host, result: unknown(null, 'NOT_PROBED', '等待检测') };
}

function currentItemFromTxtAddress(record: DnsRecord, address: string, target: ManagedTarget): CurrentMaintenanceItem | null {
  const parsed = parseProxyTarget(address, target.port ?? 443);
  if (!parsed) return invalidDnsItem(record, address);
  return { recordId: record.id, address: parsed.authority, value: parsed.authority, result: unknown(null, 'NOT_PROBED', '等待检测') };
}

function invalidDnsItem(record: DnsRecord, value: string): CurrentMaintenanceItem {
  return { recordId: record.id, address: value, value, result: unknown(null, 'INVALID_DNS_VALUE', 'DNS 记录内容无法解析') };
}

async function probeSafely(probe: ProbeAdapter, item: Pick<CurrentMaintenanceItem, 'address'>, target: ManagedTarget, signal?: AbortSignal): Promise<ProbeResult> {
  signal?.throwIfAborted();
  const parsed = parseProxyTarget(item.address, target.port ?? 443);
  if (!parsed) return unknown(null, 'INVALID_DNS_VALUE', 'DNS 记录内容无法解析');
  try { return await probe.probe(parsed, signal ? { signal } : {}); }
  catch {
    signal?.throwIfAborted();
    return unknown(parsed, 'PROBE_ERROR', '检测执行异常');
  }
}

function parsePoolEntries(text: string) { return [...readPoolSnapshot(text).entries.values()].map(item => item.entry); }
function incompleteProbe({ result }: Pick<CandidateMaintenanceItem, 'result'>): boolean {
  return result.code === 'PROBE_BUDGET_EXHAUSTED' || result.code === 'SUBREQUEST_LIMIT';
}
function sameValues(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const values = new Set(right);
  return left.every(value => values.has(value));
}
function uniqueValues(values: readonly string[]): string[] { return [...new Set(values.map(value => value.trim()).filter(Boolean))]; }
function isPresent<T>(value: T | null): value is T { return value !== null; }
