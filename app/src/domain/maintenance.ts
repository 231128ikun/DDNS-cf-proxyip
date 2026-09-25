import { probeMatchesTarget, type ManagedTarget } from './managed-target';
import {
  canonicalAddressKey,
  formatPoolEntry,
  parsePoolText,
  serializePoolText,
  updatePoolEntryFromProbe,
  type PoolEntry,
  type PoolLine,
} from './pool-entry';
import type { ProbeResult } from './probe-result';

export type MaintenanceDecision = 'active' | 'remove-dead' | 'remove-mismatch' | 'keep-unknown';

export interface CurrentMaintenanceItem {
  readonly recordId: string | null;
  readonly address: string;
  readonly value: string;
  readonly result: ProbeResult;
}

export interface CandidateMaintenanceItem {
  readonly entry: PoolEntry;
  readonly address: string;
  readonly value: string;
  readonly result: ProbeResult;
}

export interface CurrentMaintenanceDecision {
  readonly item: CurrentMaintenanceItem;
  readonly decision: MaintenanceDecision;
}

export interface MaintenanceTrashItem {
  readonly entryLine: string;
  readonly reason: string;
}

export interface MaintenancePlanInput {
  readonly target: ManagedTarget;
  readonly current: readonly CurrentMaintenanceItem[];
  readonly candidates: readonly CandidateMaintenanceItem[];
  readonly poolText: string;
}

export interface MaintenancePlan {
  readonly target: ManagedTarget;
  readonly current: readonly CurrentMaintenanceDecision[];
  readonly additions: readonly CandidateMaintenanceItem[];
  readonly retainedValues: readonly string[];
  readonly dnsValues: readonly string[];
  readonly nextPoolText: string;
  readonly poolChanged: boolean;
  readonly trash: readonly MaintenanceTrashItem[];
  readonly activeCount: number;
  readonly exhausted: boolean;
}

export function decideCurrentResult(result: ProbeResult, target: ManagedTarget): MaintenanceDecision {
  if (result.status === 'unknown') return 'keep-unknown';
  if (result.status === 'dead') return 'remove-dead';
  return probeMatchesTarget(result, target) ? 'active' : 'remove-mismatch';
}

export function buildMaintenancePlan(input: MaintenancePlanInput): MaintenancePlan {
  const originalPoolText = input.poolText;
  let poolLines = parsePoolText(originalPoolText);
  const trash: MaintenanceTrashItem[] = [];
  const current = input.current.map((item) => ({
    item,
    decision: decideCurrentResult(item.result, input.target),
  }));
  const retained = current.filter(({ decision }) => decision === 'active' || decision === 'keep-unknown');
  const additions: CandidateMaintenanceItem[] = [];
  let activeCount = current.filter(({ decision }) => decision === 'active').length;

  const updatePoolMetadata = (address: string, result: ProbeResult): void => {
    if (result.status !== 'alive') return;
    const key = canonicalAddressKey(address);
    poolLines = poolLines.map((line) => refreshLine(line, key, result));
  };

  const removePoolEntry = (address: string, reason: string, alwaysTrash: boolean): void => {
    const key = canonicalAddressKey(address);
    let matched = false;
    const next: PoolLine[] = [];
    for (const line of poolLines) {
      if (line.entry && canonicalAddressKey(line.entry.address) === key) {
        if (!matched) trash.push({ entryLine: line.raw, reason });
        matched = true;
        continue;
      }
      next.push(line);
    }
    poolLines = next;
    if (!matched && alwaysTrash) trash.push({ entryLine: address, reason });
  };

  for (const { item, decision } of current) {
    if (decision === 'active') {
      updatePoolMetadata(item.address, item.result);
    } else if (decision === 'remove-mismatch') {
      updatePoolMetadata(item.address, item.result);
    } else if (decision === 'remove-dead') {
      removePoolEntry(item.address, '维护失效', true);
    }
  }

  for (const candidate of input.candidates) {
    if (activeCount >= input.target.minActive) break;

    if (candidate.result.status === 'alive' && probeMatchesTarget(candidate.result, input.target)) {
      additions.push(candidate);
      activeCount += 1;
      updatePoolMetadata(candidate.address, candidate.result);
      continue;
    }

    if (candidate.result.status === 'alive') {
      updatePoolMetadata(candidate.address, candidate.result);
      continue;
    }

    if (candidate.result.status === 'dead') {
      removePoolEntry(candidate.address, '维护失效', false);
    }
  }

  const retainedValues = uniqueNonEmpty(retained.map(({ item }) => item.value));
  const dnsValues = uniqueNonEmpty([...retainedValues, ...additions.map((candidate) => candidate.value)]);
  const nextPoolText = serializePoolText(poolLines);

  return {
    target: input.target,
    current,
    additions,
    retainedValues,
    dnsValues,
    nextPoolText,
    poolChanged: nextPoolText !== originalPoolText,
    trash,
    activeCount,
    exhausted: activeCount < input.target.minActive,
  };
}

function refreshLine(line: PoolLine, addressKey: string, result: ProbeResult): PoolLine {
  if (!line.entry || canonicalAddressKey(line.entry.address) !== addressKey) return line;
  const refreshed = updatePoolEntryFromProbe(line.entry, result);
  const raw = formatPoolEntry(refreshed);
  return raw === line.raw ? line : { raw, entry: refreshed };
}

function uniqueNonEmpty(values: readonly string[]): readonly string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
