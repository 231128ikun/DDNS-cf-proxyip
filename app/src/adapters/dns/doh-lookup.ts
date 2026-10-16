import type {
  DnsLookup,
  DnsLookupContext,
  DnsLookupFailureCode,
  DnsLookupResult,
  DnsLookupType,
} from '../../ports/dns-lookup';
import { createRequestTimeout } from '../../util/request-timeout';

/** IANA 记录类型编号，用于从 DoH JSON 响应里挑出需要的 Answer。 */
const TYPE_CODES: Readonly<Record<DnsLookupType, number>> = { A: 1, AAAA: 28, TXT: 16 };

const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_ANSWERS = 50;

export interface DohLookupOptions {
  /** DoH JSON 接口地址，例如 https://cloudflare-dns.com/dns-query。 */
  readonly endpoint: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

/**
 * RFC 8427 的 DoH JSON 适配器（Cloudflare / Google 等公共解析都支持）。
 * 任何异常都转成失败结果，由用例层决定是回退还是标记 unknown。
 */
export class DohLookup implements DnsLookup {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: DohLookupOptions) {
    this.endpoint = options.endpoint.trim();
    this.timeoutMs = Math.max(1_000, Math.min(30_000, options.timeoutMs ?? DEFAULT_TIMEOUT_MS));
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async query(name: string, type: DnsLookupType, context: DnsLookupContext = {}): Promise<DnsLookupResult> {
    if (!this.endpoint) return fail('HTTP_ERROR', '未配置 DoH 接口');

    const url = `${this.endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const timeout = createRequestTimeout(this.timeoutMs, context.signal);

    try {
      const response = await this.fetchImpl(url, {
        headers: { accept: 'application/dns-json' },
        signal: timeout.signal,
      });
      if (!response.ok) return fail('HTTP_ERROR', `DoH 接口返回 HTTP ${response.status}`);

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        return fail('BAD_RESPONSE', 'DoH 响应不是有效 JSON');
      }
      return parseDohPayload(payload, type);
    } catch {
      if (context.signal?.aborted) return fail('ABORTED', 'DoH 查询已取消');
      if (timeout.didTimeout()) return fail('TIMEOUT', 'DoH 查询超时');
      return fail('NETWORK_ERROR', 'DoH 接口网络异常');
    } finally {
      timeout.cleanup();
    }
  }
}

/** 解析 DoH JSON：Status 不为 0 说明解析器明确失败，Answer 之外的字段一律忽略。 */
export function parseDohPayload(payload: unknown, type: DnsLookupType): DnsLookupResult {
  const record = asRecord(payload);
  if (!record) return fail('BAD_RESPONSE', 'DoH 响应不是对象');

  const status = record.Status;
  if (typeof status !== 'number' || !Number.isInteger(status)) return fail('BAD_RESPONSE', 'DoH 响应缺少 Status');
  if (status !== 0) return fail('DNS_STATUS', `DoH 返回状态 ${status}`);

  const answers = Array.isArray(record.Answer) ? record.Answer : [];
  const values: string[] = [];
  const seen = new Set<string>();
  for (const answer of answers) {
    const item = asRecord(answer);
    if (!item || item.type !== TYPE_CODES[type] || typeof item.data !== 'string') continue;
    const value = item.data.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    values.push(value);
    if (values.length >= MAX_ANSWERS) break;
  }
  return { ok: true, values };
}

function fail(code: DnsLookupFailureCode, message: string): DnsLookupResult {
  return { ok: false, code, message };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
