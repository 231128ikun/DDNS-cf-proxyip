import type { PoolSaveMode, PoolSaveResponse, PoolSummary, RestoreTrashResponse } from '../contracts/pool';
import {
  DEFAULT_POOL_KEY,
  MAX_POOL_DISPLAY_NAME_LENGTH,
  NUMBERED_POOL_KEY_RE,
  TRASH_POOL_KEY,
  isPoolDataKey,
  isUserPoolKey,
} from '../contracts/pool';
import { canonicalAddressKey } from '../domain/pool-entry';
import { normalizePoolOrder } from '../domain/pool-order';
import { readPoolSnapshot, type PoolSnapshot } from '../domain/pool-snapshot';
import { planPoolSave, planPoolRestore } from '../domain/pool-mutation';
import { sourcePoolFromTrash } from '../domain/trash';
import { executePoolWrites } from './pool-write';
import type { PoolCatalog } from '../ports/pool-catalog';

/** KV 单值上限远大于此值，这里限制的是面板一次能提交的池大小，避免误粘贴超大文本。 */
export const MAX_POOL_CONTENT_LENGTH = 512_000;

export class PoolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PoolInputError';
  }
}

export class PoolService {
  constructor(private readonly catalog: PoolCatalog) {}

  async list(): Promise<readonly PoolSummary[]> {
    return await this.catalog.list();
  }

  async read(poolKey: unknown): Promise<string> {
    return await this.catalog.read(requirePoolKey(poolKey));
  }

  async save(poolKey: unknown, content: unknown, modeValue?: unknown, returnReceiptValue?: unknown, expectedContent?: string): Promise<PoolSaveResponse> {
    if (returnReceiptValue !== undefined && typeof returnReceiptValue !== 'boolean') throw new PoolInputError('returnReceipt 必须是布尔值');
    const plan = await this.prepareSave(poolKey, content, modeValue, expectedContent);
    await executePoolWrites([plan.write], (key, text) => this.catalog.write(key, text));
    return { ok: true, ...plan.summary,
      ...(returnReceiptValue === true ? { receipt: { poolKey: plan.write.poolKey, content: plan.write.after, written: plan.changed } } : {}),
    };
  }

  private async prepareSave(poolKey: unknown, content: unknown, modeValue?: unknown, expectedContent?: string) {
    const key = requirePoolKey(poolKey);
    if (key === TRASH_POOL_KEY) throw new PoolInputError('垃圾桶只能由维护和洗库流程写入');
    const mode = parseSaveMode(modeValue);
    const incoming = readPoolSnapshot(normalizeContent(content));
    if (incoming.invalid.length) throw new PoolInputError('包含无法识别的条目，原池未修改');
    if (mode !== 'replace' && incoming.entries.size === 0) throw new PoolInputError('没有有效 IP');
    const current = await this.catalog.read(key);
    if (expectedContent !== undefined && current !== expectedContent) throw new PoolInputError('库存已变化，未替换原池，请重新洗库');
    return planPoolSave(key, readPoolSnapshot(current), incoming, mode);
  }

  async create(displayNameValue: unknown): Promise<PoolSummary> {
    return await this.catalog.create(normalizeDisplayName(displayNameValue));
  }

  async rename(poolKey: unknown, displayNameValue: unknown): Promise<void> {
    const key = requireUserPoolKey(poolKey);
    const displayName = normalizeDisplayName(displayNameValue);
    if (!await this.catalog.exists(key)) throw new PoolInputError('池不存在');
    await this.catalog.rename(key, displayName);
  }

  async remove(poolKey: unknown): Promise<void> {
    const key = requirePoolKey(poolKey);
    if (!NUMBERED_POOL_KEY_RE.test(key)) throw new PoolInputError('只能删除编号 IP 池');
    if (!await this.catalog.exists(key)) throw new PoolInputError('池不存在');
    await this.catalog.remove(key);
  }

  async saveOrder(orderValue: unknown): Promise<void> {
    if (!Array.isArray(orderValue) || orderValue.some((key) => typeof key !== 'string')) {
      throw new PoolInputError('排序数据格式无效');
    }

    const actual = await this.list();
    const actualKeys = actual.map((pool) => pool.key);
    const actualSet = new Set(actualKeys);
    const submitted = [...new Set(orderValue.map((key) => key.trim()).filter(Boolean))];
    if (submitted.length !== actualKeys.length || submitted.some((key) => !actualSet.has(key))) {
      throw new PoolInputError('池列表已变化，请刷新后重试');
    }
    await this.catalog.saveOrder(normalizePoolOrder(submitted, actualKeys));
  }

  async clearTrash(): Promise<void> {
    await executePoolWrites([{ poolKey: TRASH_POOL_KEY, before: await this.catalog.read(TRASH_POOL_KEY), after: '' }],
      (key, text) => this.catalog.write(key, text));
  }

  async restoreTrash(
    addressesValue: unknown,
    restoreToSourceValue?: unknown,
    targetPoolValue?: unknown,
    expectedContent?: string,
  ): Promise<RestoreTrashResponse> {
    if (!Array.isArray(addressesValue) || addressesValue.some((value) => typeof value !== 'string')) {
      throw new PoolInputError('addresses 必须是数组');
    }
    if (addressesValue.length === 0) throw new PoolInputError('没有选择 IP');

    const requested = [...new Set(addressesValue.map((value) => canonicalAddressKey(value)).filter(Boolean))];
    if (requested.length === 0) throw new PoolInputError('没有有效 IP');

    const restoreToSource = restoreToSourceValue === true;
    const fallbackPool = restoreToSource ? DEFAULT_POOL_KEY : requireUserPoolKey(targetPoolValue ?? DEFAULT_POOL_KEY);
    const content = await this.catalog.read(TRASH_POOL_KEY);
    if (expectedContent !== undefined && content !== expectedContent) throw new PoolInputError('垃圾桶库存已变化，请重新洗库');
    const trash = readPoolSnapshot(content);
    const destinations = new Map<string, PoolSnapshot>();
    const assignments = new Map<string, string>();
    const sourcePools = new Map<string, string>();
    for (const key of requested) {
      const item = trash.entries.get(key);
      if (!item) continue;
      const poolKey = restoreToSource ? await this.resolveSourcePool(item.raw, fallbackPool, sourcePools) : fallbackPool;
      assignments.set(key, poolKey);
      if (!destinations.has(poolKey)) destinations.set(poolKey, readPoolSnapshot(await this.catalog.read(poolKey)));
    }
    const plan = planPoolRestore(trash, destinations, assignments);
    await executePoolWrites(plan.writes, (key, text) => this.catalog.write(key, text));
    return { ok: true, ...plan.summary };
  }

  private async resolveSourcePool(trashLine: string, fallbackPool: string, resolved: Map<string, string>): Promise<string> {
    const candidate = sourcePoolFromTrash(trashLine);
    if (!candidate) return fallbackPool;
    if (resolved.has(candidate)) return resolved.get(candidate)!;
    const pool = candidate === DEFAULT_POOL_KEY || await this.catalog.exists(candidate) ? candidate : fallbackPool;
    resolved.set(candidate, pool);
    return pool;
  }
}

function requirePoolKey(value: unknown): string {
  const key = typeof value === 'string' ? value.trim() : '';
  if (!isPoolDataKey(key)) throw new PoolInputError('IP 池标识无效');
  return key;
}

function requireUserPoolKey(value: unknown): string {
  const key = typeof value === 'string' ? value.trim() : '';
  if (!isUserPoolKey(key)) throw new PoolInputError('目标池无效');
  return key;
}

function normalizeDisplayName(value: unknown): string {
  const displayName = typeof value === 'string' ? value.trim() : '';
  if (!displayName) throw new PoolInputError('显示名称不能为空');
  if (displayName.length > MAX_POOL_DISPLAY_NAME_LENGTH || /[\r\n]/.test(displayName)) {
    throw new PoolInputError(`显示名称不能超过 ${MAX_POOL_DISPLAY_NAME_LENGTH} 个字符且不能换行`);
  }
  return displayName;
}

function parseSaveMode(value: unknown): PoolSaveMode {
  if (value === undefined || value === null || value === '') return 'append';
  if (value === 'append' || value === 'replace' || value === 'remove') return value;
  throw new PoolInputError('IP 池写入模式无效');
}

function normalizeContent(value: unknown): string {
  if (typeof value !== 'string') throw new PoolInputError('IP 池内容必须是文本');
  if (value.length > MAX_POOL_CONTENT_LENGTH) throw new PoolInputError('IP 池内容超出长度限制');
  return value.replace(/\r\n?/g, '\n').trim();
}
