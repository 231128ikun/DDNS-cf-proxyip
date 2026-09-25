import type { PoolSaveMode, PoolSaveResponse, PoolSummary, RestoreTrashResponse } from '../contracts/pool';
import {
  DEFAULT_POOL_KEY,
  MAX_POOL_DISPLAY_NAME_LENGTH,
  MAX_POOL_RESTORE_ITEMS,
  NUMBERED_POOL_KEY_RE,
  TRASH_POOL_KEY,
  isPoolDataKey,
  isUserPoolKey,
} from '../contracts/pool';
import {
  canonicalAddressKey,
  formatPoolEntry,
  mergePoolEntry,
  parsePoolAddress,
  parsePoolText,
  type PoolEntry,
} from '../domain/pool-entry';
import type { PoolCatalog } from '../ports/pool-catalog';

/** KV 单值上限远大于此值，这里限制的是面板一次能提交的池大小，避免误粘贴超大文本。 */
export const MAX_POOL_CONTENT_LENGTH = 512_000;

export class PoolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PoolInputError';
  }
}

/** IP 池管理用例：只做输入校验与规范化，真正的存取交给 PoolCatalog。 */
export class PoolService {
  constructor(private readonly catalog: PoolCatalog) {}

  async list(): Promise<readonly PoolSummary[]> {
    return await this.catalog.list();
  }

  async read(poolKey: unknown): Promise<string> {
    return await this.catalog.read(requirePoolKey(poolKey));
  }

  async save(poolKey: unknown, content: unknown, modeValue?: unknown): Promise<PoolSaveResponse> {
    const key = requirePoolKey(poolKey);
    const mode = parseSaveMode(modeValue);
    const incoming = poolEntryMap(normalizeContent(content));
    const existing = poolEntryMap(await this.catalog.read(key));
    const existingCount = existing.size;
    let added = 0;
    let removed = 0;
    let replaced = 0;

    if (mode === 'append') {
      if (incoming.size === 0) throw new PoolInputError('没有有效 IP');
      for (const [addressKey, entry] of incoming) {
        const previous = existing.get(addressKey);
        existing.set(addressKey, previous ? mergePoolEntry(previous, entry) : entry);
      }
      added = existing.size - existingCount;
    } else if (mode === 'remove') {
      for (const addressKey of incoming.keys()) {
        if (existing.delete(addressKey)) removed += 1;
      }
    } else {
      replaced = existingCount;
      added = incoming.size;
      existing.clear();
      for (const [addressKey, entry] of incoming) existing.set(addressKey, entry);
    }

    await this.catalog.write(key, serializeEntries(existing));
    return { ok: true, mode, count: existing.size, added, removed, replaced };
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
    await this.catalog.write(TRASH_POOL_KEY, '');
  }

  async restoreTrash(
    addressesValue: unknown,
    restoreToSourceValue?: unknown,
    targetPoolValue?: unknown,
  ): Promise<RestoreTrashResponse> {
    if (!Array.isArray(addressesValue) || addressesValue.some((value) => typeof value !== 'string')) {
      throw new PoolInputError('addresses 必须是数组');
    }
    if (addressesValue.length === 0) throw new PoolInputError('没有选择 IP');
    if (addressesValue.length > MAX_POOL_RESTORE_ITEMS) throw new PoolInputError('一次恢复的 IP 数量过多');

    const requested = [...new Set(addressesValue.map((value) => canonicalAddressKey(value)).filter(Boolean))];
    if (requested.length === 0) throw new PoolInputError('没有有效 IP');

    const restoreToSource = restoreToSourceValue === true;
    const fallbackPool = restoreToSource ? DEFAULT_POOL_KEY : requireUserPoolKey(targetPoolValue ?? DEFAULT_POOL_KEY);
    const trash = poolLineMap(await this.catalog.read(TRASH_POOL_KEY));
    const targetPools = new Map<string, Map<string, PoolEntry>>();
    const restoredByPool: Record<string, number> = {};
    let restored = 0;
    let trashChanged = false;

    for (const addressKey of requested) {
      const trashItem = trash.get(addressKey);
      if (!trashItem) continue;
      trash.delete(addressKey);
      trashChanged = true;

      const targetPool = restoreToSource
        ? await this.resolveSourcePool(trashItem.raw, fallbackPool)
        : fallbackPool;
      let targetEntries = targetPools.get(targetPool);
      if (!targetEntries) {
        targetEntries = poolEntryMap(await this.catalog.read(targetPool));
        targetPools.set(targetPool, targetEntries);
      }
      if (targetEntries.has(addressKey)) continue;

      targetEntries.set(addressKey, { ...trashItem.entry, comment: '' });
      restored += 1;
      restoredByPool[targetPool] = (restoredByPool[targetPool] ?? 0) + 1;
    }

    if (trashChanged) await this.catalog.write(TRASH_POOL_KEY, serializeEntries(lineEntriesToEntries(trash)));
    for (const [poolKey, entries] of targetPools) {
      if ((restoredByPool[poolKey] ?? 0) > 0) await this.catalog.write(poolKey, serializeEntries(entries));
    }
    return { ok: true, restored, restoredByPool };
  }

  private async resolveSourcePool(trashLine: string, fallbackPool: string): Promise<string> {
    const marker = ' 来自 ';
    const markerIndex = trashLine.lastIndexOf(marker);
    if (markerIndex < 0) return fallbackPool;
    const candidate = trashLine.slice(markerIndex + marker.length).trim();
    if (!isUserPoolKey(candidate)) return fallbackPool;
    return candidate === DEFAULT_POOL_KEY || await this.catalog.exists(candidate) ? candidate : fallbackPool;
  }
}

interface PoolLineItem {
  readonly raw: string;
  readonly entry: PoolEntry;
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

function poolEntryMap(text: string): Map<string, PoolEntry> {
  const entries = new Map<string, PoolEntry>();
  for (const line of poolLineMap(text).values()) entries.set(canonicalAddressKey(line.entry.address), line.entry);
  return entries;
}

function poolLineMap(text: string): Map<string, PoolLineItem> {
  const entries = new Map<string, PoolLineItem>();
  for (const line of parsePoolText(text)) {
    const entry = line.entry;
    if (!entry || !parsePoolAddress(entry)) continue;
    const key = canonicalAddressKey(entry.address);
    if (key) entries.set(key, { raw: line.raw, entry });
  }
  return entries;
}

function lineEntriesToEntries(lines: ReadonlyMap<string, PoolLineItem>): Map<string, PoolEntry> {
  return new Map([...lines].map(([key, line]) => [key, line.entry]));
}

function serializeEntries(entries: ReadonlyMap<string, PoolEntry>): string {
  return [...entries.values()].map((entry) => formatPoolEntry(entry)).join('\n');
}

function normalizePoolOrder(submitted: readonly string[], actual: readonly string[]): readonly string[] {
  const submittedSet = new Set(submitted);
  const middle = submitted.filter((key) => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY && submittedSet.has(key));
  const actualMiddle = actual.filter((key) => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY);
  for (const key of actualMiddle) if (!middle.includes(key)) middle.push(key);

  return [
    ...(actual.includes(DEFAULT_POOL_KEY) ? [DEFAULT_POOL_KEY] : []),
    ...middle,
    ...(actual.includes(TRASH_POOL_KEY) ? [TRASH_POOL_KEY] : []),
  ];
}


