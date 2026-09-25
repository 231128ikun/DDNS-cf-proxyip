import { dnsRecordTypeForHost, formatProxyAuthority } from '../domain/proxy-target';
import { parseTxtAddresses } from '../domain/txt-record';
import {
  activeValueForEntry,
  selectCandidateEntries,
  type ManagedTarget,
} from '../domain/managed-target';
import {
  buildMaintenancePlan,
  decideCurrentResult,
  type CandidateMaintenanceItem,
  type CurrentMaintenanceItem,
  type MaintenancePlan,
} from '../domain/maintenance';
import { canonicalAddressKey, parsePoolText, type PoolEntry } from '../domain/pool-entry';
import { parseProxyTarget } from '../domain/proxy-target';
import { mapWithConcurrency } from '../util/concurrency';
import { isProbeErrorResult, unknown, type ProbeResult } from '../domain/probe-result';
import type { DnsRecord, DnsRepository, DnsZone } from '../ports/dns-repository';
import type { PoolRepository } from '../ports/pool-repository';
import type { ProbeAdapter } from '../ports/probe';

export interface MaintainManagedTargetCommand {
  readonly target: ManagedTarget;
  readonly zone: DnsZone;
  readonly poolKey: string;
}

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
  /** 本轮遇到的检测接口异常次数；> 0 时通知用户人工确认，且不据此删除任何记录。 */
  readonly probeErrors: number;
  readonly errors: readonly string[];
}

export class MaintainManagedTarget {
  private readonly concurrency: number;

  constructor(private readonly dependencies: MaintainManagedTargetDependencies) {
    this.concurrency = Math.max(1, Math.min(8, dependencies.concurrency ?? 4));
  }

  async execute(command: MaintainManagedTargetCommand): Promise<MaintenanceReport> {
    const poolText = await this.dependencies.pools.load(command.poolKey);
    const current = await this.probeCurrentRecords(command);
    const currentDecisions = current.map((item) => ({
      item,
      decision: decideCurrentResult(item.result, command.target),
    }));
    const excludedAddresses = new Set(
      currentDecisions
        .filter(({ decision }) => decision !== 'remove-dead' && decision !== 'remove-mismatch')
        .map(({ item }) => canonicalAddressKey(item.address)),
    );
    const activeCount = currentDecisions.filter(({ decision }) => decision === 'active').length;
    const candidates = selectCandidateEntries(
      parsePoolEntries(poolText),
      command.target,
      excludedAddresses,
    );
    const probedCandidates = await this.probeCandidatesUntilTarget(command.target, candidates, activeCount);
    const plan = buildMaintenancePlan({ target: command.target, current, candidates: probedCandidates, poolText });
    const probeErrors = current.filter((item) => isProbeErrorResult(item.result)).length
      + probedCandidates.filter((item) => isProbeErrorResult(item.result)).length;
    const errors: string[] = [];
    const dnsResult = await this.applyDnsChanges(command, plan, errors);

    if (plan.poolChanged) {
      try {
        await this.dependencies.pools.save(command.poolKey, plan.nextPoolText);
      } catch {
        errors.push('保存 IP 池失败');
      }
    }

    if (plan.trash.length > 0) {
      try {
        await this.dependencies.pools.addToTrash(
          plan.trash.map((item) => ({ ...item, poolKey: command.poolKey })),
        );
      } catch {
        errors.push('写入垃圾桶失败');
      }
    }

    return {
      target: command.target,
      poolKey: command.poolKey,
      plan,
      deleted: dnsResult.deleted,
      added: dnsResult.added,
      dnsUpdated: dnsResult.updated,
      probeErrors,
      errors,
    };
  }

  private async probeCurrentRecords(command: MaintainManagedTargetCommand): Promise<CurrentMaintenanceItem[]> {
    if (command.target.mode === 'A') {
      const records = await this.dependencies.dns.listAddressRecords(command.zone, command.target.domain);
      const items = records.map((record) => currentItemFromAddressRecord(record, command.target)).filter(isPresent);
      return await mapWithConcurrency(items, this.concurrency, async (item) => ({
        ...item,
        result: await probeSafely(this.dependencies.probe, item, command.target),
      }));
    }

    const records = await this.dependencies.dns.listTxtRecords(command.zone, command.target.domain);
    const record = records[0];
    if (!record) return [];
    const items = parseTxtAddresses(record.content)
      .map((address) => currentItemFromTxtAddress(record, address, command.target))
      .filter(isPresent);
    return await mapWithConcurrency(items, this.concurrency, async (item) => ({
      ...item,
      result: await probeSafely(this.dependencies.probe, item, command.target),
    }));
  }

  private async probeCandidatesUntilTarget(
    target: ManagedTarget,
    candidates: readonly PoolEntry[],
    currentActiveCount: number,
  ): Promise<CandidateMaintenanceItem[]> {
    const results: CandidateMaintenanceItem[] = [];
    let activeCount = currentActiveCount;

    for (const entry of candidates) {
      if (activeCount >= target.minActive) break;
      const parsed = parseProxyTarget(entry.address, target.port ?? 443);
      if (!parsed) continue;
      const address = target.mode === 'A' && target.port
        ? formatProxyAuthority(parsed.host, target.port)
        : parsed.authority;
      const item = {
        entry,
        address,
        value: activeValueForEntry(entry, target),
      };
      const result = await probeSafely(this.dependencies.probe, item, target);
      results.push({ ...item, result });
      if (result.status === 'alive' && resultMatchesTarget(result, target)) activeCount += 1;
    }

    return results;
  }

  private async applyDnsChanges(
    command: MaintainManagedTargetCommand,
    plan: MaintenancePlan,
    errors: string[],
  ): Promise<{ deleted: number; added: number; updated: boolean }> {
    if (command.target.mode === 'A') {
      let deleted = 0;
      let added = 0;
      for (const { item, decision } of plan.current) {
        if ((decision !== 'remove-dead' && decision !== 'remove-mismatch') || !item.recordId) continue;
        try {
          await this.dependencies.dns.deleteRecord(command.zone, item.recordId);
          deleted += 1;
        } catch {
          errors.push(`删除 DNS 记录失败: ${item.value}`);
        }
      }

      for (const candidate of plan.additions) {
        try {
          await this.dependencies.dns.addAddressRecord(
            command.zone,
            command.target.domain,
            candidate.value,
            dnsRecordTypeForHost(candidate.value),
          );
          added += 1;
        } catch {
          errors.push(`添加 DNS 记录失败: ${candidate.value}`);
        }
      }
      return { deleted, added, updated: deleted > 0 || added > 0 };
    }

    const original = uniqueValues(plan.current.map(({ item }) => item.value));
    if (sameValues(original, plan.dnsValues)) return { deleted: 0, added: 0, updated: false };

    try {
      if (plan.dnsValues.length === 0) {
        const recordId = plan.current.find(({ item }) => item.recordId)?.item.recordId;
        if (recordId) await this.dependencies.dns.deleteRecord(command.zone, recordId);
        return { deleted: recordId ? 1 : 0, added: 0, updated: Boolean(recordId) };
      }
      const recordId = plan.current.find(({ item }) => item.recordId)?.item.recordId ?? null;
      await this.dependencies.dns.upsertTxtRecord(command.zone, command.target.domain, recordId, plan.dnsValues);
      return { deleted: 0, added: 0, updated: true };
    } catch {
      errors.push('更新 TXT 记录失败');
      return { deleted: 0, added: 0, updated: false };
    }
  }
}

function currentItemFromAddressRecord(record: DnsRecord, target: ManagedTarget): CurrentMaintenanceItem | null {
  const parsed = parseProxyTarget(record.content, target.port ?? 443);
  const expectedFamily = record.type === 'AAAA' ? 'ipv6' : 'ipv4';
  if (!parsed || parsed.family !== expectedFamily) return invalidDnsItem(record, record.content);
  return {
    recordId: record.id,
    address: target.port ? formatProxyAuthority(parsed.host, target.port) : parsed.authority,
    value: parsed.host,
    result: unknown(null, 'NOT_PROBED', '等待检测'),
  };
}

function currentItemFromTxtAddress(record: DnsRecord, address: string, target: ManagedTarget): CurrentMaintenanceItem | null {
  const parsed = parseProxyTarget(address, target.port ?? 443);
  if (!parsed) return invalidDnsItem(record, address);
  return {
    recordId: record.id,
    address: parsed.authority,
    value: parsed.authority,
    result: unknown(null, 'NOT_PROBED', '等待检测'),
  };
}

function invalidDnsItem(record: DnsRecord, value: string): CurrentMaintenanceItem {
  return {
    recordId: record.id,
    address: value,
    value,
    result: unknown(null, 'INVALID_DNS_VALUE', 'DNS 记录内容无法解析'),
  };
}

async function probeSafely(
  probe: ProbeAdapter,
  item: Pick<CurrentMaintenanceItem, 'address'>,
  target: ManagedTarget,
): Promise<ProbeResult> {
  const parsed = parseProxyTarget(item.address, target.port ?? 443);
  if (!parsed) return unknown(null, 'INVALID_DNS_VALUE', 'DNS 记录内容无法解析');
  try {
    return await probe.probe(parsed);
  } catch {
    return unknown(parsed, 'PROBE_ERROR', '检测执行异常');
  }
}

function resultMatchesTarget(result: ProbeResult, target: ManagedTarget): boolean {
  return decideCurrentResult(result, target) === 'active';
}

function parsePoolEntries(text: string) {
  return parsePoolText(text)
    .map((line) => line.entry)
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
}

function sameValues(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return left.every((value) => rightSet.has(value));
}

function uniqueValues(values: readonly string[]): readonly string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function isPresent<T>(value: T | null): value is T {
  return value !== null;
}
