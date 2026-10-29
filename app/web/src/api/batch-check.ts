import { ApiError, type ApiClient } from './client';
import type { PoolCheckItemResponse, PoolCheckProgressEvent, PoolCheckResponse } from '../../../src/contracts/pool-check';
import type { CheckTargetResponse } from '../../../src/contracts/probe';
import { formatPoolEntry, parsePoolEntry, parsePoolText, updatePoolEntryFromProbe } from '../../../src/domain/pool-entry';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
import { DEFAULT_RUNTIME_SETTINGS, SETTINGS_LIMITS } from '../../../src/contracts/runtime-settings';
import { readClampedInteger } from '../../../src/contracts/parse';
import { mapWithConcurrency } from '../../../src/util/concurrency';

export async function checkBatch(client: Pick<ApiClient, 'checkTarget'>,
  text: string,
  signal?: AbortSignal,
  onProgress?: (event: PoolCheckProgressEvent) => void,
  concurrency: number = DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS,
): Promise<PoolCheckResponse> {
  const { targets, invalid } = parsePoolCheckTargets(text);
  let completed = 0;
  let total = targets.length;

  const { min, max } = SETTINGS_LIMITS.CONCURRENT_CHECKS;
  const limit = readClampedInteger(concurrency, DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS, min, max);
  const itemGroups = await mapWithConcurrency(targets, limit, async (target) => {
    if (signal?.aborted) throw new DOMException('检测已取消', 'AbortError');
    const checked = await checkPoolTarget(client, target, signal);
    total += checked.length - 1;
    for (const [index, item] of checked.entries()) {
      completed += 1;
      onProgress?.({
        type: 'progress',
        completed,
        total,
        item,
        sourceIndex: target.sourceIndex,
        sourceComplete: index === checked.length - 1,
      });
    }
    return checked;
  });
  const items = itemGroups.flat();

  return {
    total: items.length,
    alive: items.filter((item) => item.status === 'alive').length,
    dead: items.filter((item) => item.status === 'dead').length,
    unknown: items.filter((item) => item.status === 'unknown').length,
    invalid,
    items,
  };
}

async function checkPoolTarget(client: Pick<ApiClient, 'checkTarget'>,
  target: ParsedPoolCheckTarget,
  signal?: AbortSignal,
): Promise<readonly PoolCheckItemResponse[]> {
  let results: CheckTargetResponse['items'] = [];
  try {
    const response = await client.checkTarget(target.entry.address, signal);
    if (Array.isArray(response.items) && response.items.length > 0) {
      if (!response.items.every(isCheckTargetItemResponse)) {
        throw new ApiError('检测响应格式无效', 200);
      }
      results = response.items;
    }
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === 'AbortError')) throw error;
    results = [unknownCheckItem(target.target.authority,
      error instanceof ApiError ? `HTTP_${error.status}` : 'REQUEST_FAILED',
      error instanceof Error ? error.message : '检测请求异常')];
  }
  if (results.length === 0) {
    results = [unknownCheckItem(target.target.authority, 'EMPTY_RESPONSE', '检测响应缺少目标结果')];
  }

  return results.map(({ address, result }) => {
    const resolvedTarget = parseProxyTarget(address, 443) ?? target.target;
    const sourceEntry = resolvedTarget.key === target.target.key
      ? target.entry
      : { ...target.entry, address: resolvedTarget.authority };
    const entry = updatePoolEntryFromProbe(sourceEntry, { ...result, target: resolvedTarget });
    const primary = result.exits[0];
    const asn = primary?.asn ?? entry.asn ?? undefined;
    const country = primary?.country ?? entry.country ?? undefined;
    return {
      address,
      status: result.status,
      exitFamily: result.exitFamily,
      ...(result.exitIp ? { exitIp: result.exitIp } : {}),
      ...(result.latencyMs === undefined ? {} : { latencyMs: result.latencyMs }),
      ...(result.colo ? { colo: result.colo } : {}),
      ...(result.exits.length ? { exits: result.exits } : {}),
      ...(result.code ? { code: result.code } : {}),
      ...(result.message ? { message: result.message } : {}),
      ...(asn ? { asn } : {}),
      ...(country ? { country } : {}),
      line: result.status === 'unknown' ? target.sourceLine : formatPoolEntry(entry),
    };
  });
}

function unknownCheckItem(address: string, code: string, message: string): CheckTargetResponse['items'][number] {
  return { address, result: { status: 'unknown', exitFamily: 'unknown', exits: [], code, message } };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function isCheckTargetItemResponse(value: unknown): value is CheckTargetResponse['items'][number] {
  if (!isRecord(value) || typeof value.address !== 'string' || !parseProxyTarget(value.address, 443)) return false;
  if (!isRecord(value.result)) return false;
  const result = value.result;
  if (!['alive', 'dead', 'unknown'].includes(String(result.status))) return false;
  if (!['ipv4', 'ipv6', 'dual', 'unknown'].includes(String(result.exitFamily))) return false;
  return Array.isArray(result.exits) && result.exits.every((exit) => isRecord(exit));
}

interface ParsedPoolCheckTarget {
  readonly entry: NonNullable<ReturnType<typeof parsePoolEntry>>;
  readonly target: NonNullable<ReturnType<typeof parseProxyTarget>>;
  readonly sourceLine: string;
  readonly sourceIndex: number;
}

/** 复用池文本与地址规则，只负责把用户输入整理成逐个请求的目标。 */
function parsePoolCheckTargets(text: string): {
  readonly targets: readonly ParsedPoolCheckTarget[];
  readonly invalid: readonly string[];
} {
  const targets: ParsedPoolCheckTarget[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const [sourceIndex, line] of parsePoolText(text).entries()) {
    if (!line.entry) {
      invalid.push(line.raw);
      continue;
    }
    const target = parseProxyTarget(line.entry.address, 443);
    if (!target) {
      invalid.push(line.entry.address);
      continue;
    }
    if (seen.has(target.key)) continue;
    seen.add(target.key);
    targets.push({ entry: line.entry, target, sourceLine: line.raw, sourceIndex });
  }
  return { targets, invalid };
}
