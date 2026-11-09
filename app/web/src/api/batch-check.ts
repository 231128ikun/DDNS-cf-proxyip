import { ApiError, type ApiClient } from './client';
import type { PoolCheckItemResponse, PoolCheckProgressEvent, PoolCheckResponse } from '../../../src/contracts/pool-check';
import { isProbeResponse, type CheckTargetResponse } from '../../../src/contracts/probe';
import { formatPoolEntry, updatePoolEntryFromProbe, type PoolEntry } from '../../../src/domain/pool-entry';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
import { DEFAULT_RUNTIME_SETTINGS, parseRuntimeSetting } from '../../../src/contracts/runtime-settings';
import { mapWithConcurrency } from '../../../src/util/concurrency';
import { isRecord } from '../../../src/contracts/parse';

export async function checkBatch(client: Pick<ApiClient, 'checkTarget'>,
  text: string,
  signal?: AbortSignal,
  onProgress?: (event: PoolCheckProgressEvent) => void,
  concurrency: number = DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS,
): Promise<PoolCheckResponse> {
  const { targets, invalid } = parsePoolCheckTargets(text);
  let completed = 0;
  let total = targets.length;

  const limit = parseRuntimeSetting('CONCURRENT_CHECKS', concurrency);
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
    const region = primary?.region;
    const city = primary?.city;
    return {
      address,
      status: result.status,
      exitFamily: result.exitFamily,
      ...(result.exitIp ? { exitIp: result.exitIp } : {}),
      ...(result.latencyMs === undefined ? {} : { latencyMs: result.latencyMs }),
      ...(result.colo ? { colo: result.colo } : {}),
      ...(result.executionColo ? { executionColo: result.executionColo } : {}),
      ...(result.exits.length ? { exits: result.exits } : {}),
      ...(result.code ? { code: result.code } : {}),
      ...(result.message ? { message: result.message } : {}),
      ...(result.endpoint ? { endpoint: result.endpoint } : {}),
      ...(result.diagnostics?.length ? { diagnostics: result.diagnostics } : {}),
      ...(asn ? { asn } : {}),
      ...(country ? { country } : {}),
      ...(region ? { region } : {}),
      ...(city ? { city } : {}),
      line: result.status === 'unknown' ? target.sourceLine : formatPoolEntry(entry),
    };
  });
}

function unknownCheckItem(address: string, code: string, message: string): CheckTargetResponse['items'][number] {
  return { address, result: { status: 'unknown', exitFamily: 'unknown', exits: [], code, message } };
}

function isCheckTargetItemResponse(value: unknown): value is CheckTargetResponse['items'][number] {
  if (!isRecord(value) || typeof value.address !== 'string' || !parseProxyTarget(value.address, 443)) return false;
  return isProbeResponse(value.result);
}

interface ParsedPoolCheckTarget {
  readonly entry: PoolEntry;
  readonly target: NonNullable<ReturnType<typeof parseProxyTarget>>;
  readonly sourceLine: string;
  readonly sourceIndex: number;
}

/** 复用池文本与地址规则，只负责把用户输入整理成逐个请求的目标。 */
function parsePoolCheckTargets(text: string): {
  readonly targets: readonly ParsedPoolCheckTarget[];
  readonly invalid: readonly string[];
} {
  const source = readPoolSnapshot(text);
  const invalidLines = new Set(source.invalid);
  return {
    targets: [...source.entries.values()].map(item => ({ entry: item.entry, target: parseProxyTarget(item.entry.address, 443)!,
      sourceLine: item.raw, sourceIndex: item.sourceIndex })),
    // 批检仍报告独立注释行；库存快照的无损读取规则不变。
    invalid: source.lines.flatMap(line => !line.entry ? [line.raw] : invalidLines.has(line.raw) ? [line.entry.address] : []),
  };
}
