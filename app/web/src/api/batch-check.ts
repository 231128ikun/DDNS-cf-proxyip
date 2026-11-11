import { ApiError, type ApiClient } from './client';
import type { PoolCheckItemResponse, PoolCheckProgressEvent, PoolCheckResponse } from '../../../src/contracts/pool-check';
import { isCheckTargetItemResponse, MAX_CHECK_BATCH_SIZE, type CheckTargetItemResponse, type CheckTargetResponse } from '../../../src/contracts/probe';
import { formatPoolEntry, updatePoolEntryFromProbe, type PoolEntry } from '../../../src/domain/pool-entry';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { parseProxyTarget } from '../../../src/domain/proxy-target';
import { DEFAULT_RUNTIME_SETTINGS, parseRuntimeSetting } from '../../../src/contracts/runtime-settings';
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
  const emit = (target: ParsedPoolCheckTarget, item: PoolCheckItemResponse, sourceComplete = true) => {
    signal?.throwIfAborted();
    onProgress?.({ type: 'progress', completed: ++completed, total, item, sourceIndex: target.sourceIndex, sourceComplete });
  };
  const limit = parseRuntimeSetting('CONCURRENT_CHECKS', concurrency);
  // 小批量保留可用并发；大批量每组最多八项，组内按顺序检测。
  const size = Math.min(MAX_CHECK_BATCH_SIZE, Math.max(1, Math.floor(targets.length / limit)));
  const groups: ParsedPoolCheckTarget[][] = [];
  for (const target of targets) {
    const previous = groups.at(-1);
    if (target.target.family !== 'hostname' && previous && previous[0]!.target.family !== 'hostname' && previous.length < size) previous.push(target);
    else groups.push([target]);
  }
  const itemGroups = await mapWithConcurrency(groups, limit, async group => {
    signal?.throwIfAborted();
    if (group.length > 1) return await checkPoolGroup(client, group, signal, emit);
    const target = group[0]!;
    const checked = await checkPoolTarget(client, target, signal);
    total += checked.length - 1;
    checked.forEach((item, index) => emit(target, item, index === checked.length - 1));
    return checked;
  });
  const items = itemGroups.flat();
  return { total: items.length, alive: items.filter(item => item.status === 'alive').length,
    dead: items.filter(item => item.status === 'dead').length, unknown: items.filter(item => item.status === 'unknown').length, invalid, items };
}

async function checkPoolGroup(client: Pick<ApiClient, 'checkTarget'>, targets: readonly ParsedPoolCheckTarget[], signal: AbortSignal | undefined,
  emit: (target: ParsedPoolCheckTarget, item: PoolCheckItemResponse) => void): Promise<readonly PoolCheckItemResponse[]> {
  const expected = new Map(targets.map(target => [target.target.key, target]));
  const results = new Map<string, PoolCheckItemResponse>();
  const accept = (item: CheckTargetItemResponse) => {
    if (!isCheckTargetItemResponse(item)) throw new ApiError('检测结果格式无效', 200);
    const key = parseProxyTarget(item.address, 443)!.key;
    if (!expected.has(key) || results.has(key)) throw new ApiError('检测结果包含重复或组外地址', 200);
    const target = expected.get(key)!;
    const checked = toPoolCheckItem(target, item);
    results.set(key, checked);
    emit(target, checked);
  };
  let failure = unknownResult('EMPTY_RESPONSE', '检测响应缺少目标结果');
  try {
    const response = await client.checkTarget(targets.map(target => target.target.authority), signal, accept);
    // 非流式回执（例如中间层未保留 Accept）仍按整组结果处理，避免全部误判为 unknown。
    if (!results.size) response.items.forEach(accept);
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === 'AbortError')) throw error;
    failure = requestFailure(error);
  }
  for (const target of targets) if (!results.has(target.target.key)) {
    const item = toPoolCheckItem(target, { address: target.target.authority, result: failure });
    results.set(target.target.key, item);
    emit(target, item);
  }
  return targets.map(target => results.get(target.target.key)!);
}

async function checkPoolTarget(client: Pick<ApiClient, 'checkTarget'>,
  target: ParsedPoolCheckTarget,
  signal?: AbortSignal,
): Promise<readonly PoolCheckItemResponse[]> {
  let results: CheckTargetResponse['items'] = [];
  try {
    const response = await client.checkTarget(target.entry.address, signal);
    if (Array.isArray(response.items) && response.items.length > 0) {
      if (!response.items.every(isCheckTargetItemResponse)) throw new ApiError('检测响应格式无效', 200);
      results = response.items;
    }
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === 'AbortError')) throw error;
    results = [{ address: target.target.authority, result: requestFailure(error) }];
  }
  if (!results.length) results = [unknownCheckItem(target.target.authority, 'EMPTY_RESPONSE', '检测响应缺少目标结果')];
  return results.map(item => toPoolCheckItem(target, item));
}

function toPoolCheckItem(target: ParsedPoolCheckTarget, { address, result }: CheckTargetItemResponse): PoolCheckItemResponse {
  const resolvedTarget = parseProxyTarget(address, 443) ?? target.target;
  const sourceEntry = resolvedTarget.key === target.target.key ? target.entry : { ...target.entry, address: resolvedTarget.authority };
  const entry = updatePoolEntryFromProbe(sourceEntry, { ...result, target: resolvedTarget });
  const primary = result.exits[0];
  const asn = primary?.asn ?? entry.asn ?? undefined;
  const country = primary?.country ?? entry.country ?? undefined;
  const region = primary?.region;
  const city = primary?.city;
  return {
    address, status: result.status, exitFamily: result.exitFamily,
    ...(result.exitIp ? { exitIp: result.exitIp } : {}),
    ...(result.latencyMs === undefined ? {} : { latencyMs: result.latencyMs }),
    ...(result.colo ? { colo: result.colo } : {}),
    ...(result.executionColo ? { executionColo: result.executionColo } : {}),
    ...(result.exits.length ? { exits: result.exits } : {}),
    ...(result.code ? { code: result.code } : {}),
    ...(result.message ? { message: result.message } : {}),
    ...(result.endpoint ? { endpoint: result.endpoint } : {}),
    ...(result.diagnostics?.length ? { diagnostics: result.diagnostics } : {}),
    ...(asn ? { asn } : {}), ...(country ? { country } : {}), ...(region ? { region } : {}), ...(city ? { city } : {}),
    line: result.status === 'unknown' ? target.sourceLine : formatPoolEntry(entry),
  };
}

function unknownCheckItem(address: string, code: string, message: string): CheckTargetItemResponse {
  return { address, result: unknownResult(code, message) };
}

function unknownResult(code: string, message: string): CheckTargetItemResponse['result'] {
  return { status: 'unknown', exitFamily: 'unknown', exits: [], code, message };
}

function requestFailure(error: unknown): CheckTargetItemResponse['result'] {
  return unknownResult(error instanceof ApiError ? `HTTP_${error.status}` : 'REQUEST_FAILED',
    error instanceof Error ? error.message : '检测请求异常');
}

interface ParsedPoolCheckTarget {
  readonly entry: PoolEntry;
  readonly target: NonNullable<ReturnType<typeof parseProxyTarget>>;
  readonly sourceLine: string;
  readonly sourceIndex: number;
}

function parsePoolCheckTargets(text: string): { readonly targets: readonly ParsedPoolCheckTarget[]; readonly invalid: readonly string[] } {
  const source = readPoolSnapshot(text);
  return {
    targets: [...source.entries.values()].map(item => ({ entry: item.entry, target: parseProxyTarget(item.entry.address, 443)!,
      sourceLine: item.raw, sourceIndex: item.sourceIndex })),
    invalid: source.invalid,
  };
}
