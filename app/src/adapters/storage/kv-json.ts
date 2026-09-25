export type KvJsonResult =
  | { readonly status: 'missing' }
  | { readonly status: 'loaded'; readonly value: unknown }
  | { readonly status: 'invalid'; readonly message: string };

export async function readKvJson(kv: KVNamespace, key: string, cacheTtl: number): Promise<KvJsonResult> {
  const raw = await kv.get(key, { type: 'text', cacheTtl });
  if (raw === null) return { status: 'missing' };
  if (!raw.trim()) return { status: 'invalid', message: 'KV 内容为空' };

  try {
    return { status: 'loaded', value: JSON.parse(raw) };
  } catch {
    return { status: 'invalid', message: 'KV 内容不是有效 JSON' };
  }
}

/**
 * 读取 KV 里“字符串字典”形态的 JSON（池显示名、域名池绑定）。
 * 非对象、空值或非字符串字段一律忽略，读取失败按空字典处理，避免维护流程被坏数据中断。
 */
export async function readKvStringRecord(kv: KVNamespace, key: string): Promise<Record<string, string>> {
  const raw = await kv.get(key, { type: 'json' }).catch(() => null);
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return {};

  const record: Record<string, string> = {};
  for (const [field, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value === 'string' && value.trim()) record[field] = value.trim();
  }
  return record;
}