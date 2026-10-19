import { parseTxtAddresses } from '../domain/txt-record';
import { parseProxyTarget } from '../domain/proxy-target';
import type { DnsLookup, DnsLookupContext } from '../ports/dns-lookup';

/** `txt@域名` 取 TXT 列表，裸域名取 A/AAAA；两条路径都只返回地址，不负责探测。 */
export type ResolvedTargetSource =
  | { readonly kind: 'txt'; readonly host: string; readonly addresses: readonly string[] }
  | { readonly kind: 'dns'; readonly host: string; readonly addresses: readonly string[] };

export type ResolveTargetResult =
  | { readonly ok: true; readonly source: ResolvedTargetSource }
  | { readonly ok: false; readonly message: string };

export const TXT_TARGET_PREFIX = 'txt@';
const MAX_RESOLVED_ADDRESSES = 50;
/**
 * DNS 名称允许下划线开头（TXT 列表常见 `_proxy.example.com`），
 * 因此不能复用面向探测目标的严格主机名规则。
 */
const DNS_NAME_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(?:\.(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?))*$/i;

/** 判断输入是否是可以用 DNS 查询的名称（不含 IP 字面量）。 */
export function isDnsName(value: string): boolean {
  return DNS_NAME_RE.test(value.trim());
}

export function isTxtTarget(input: string): boolean {
  return input.trim().toLowerCase().startsWith(TXT_TARGET_PREFIX);
}

export class ResolveTarget {
  constructor(private readonly lookup: DnsLookup) {}

  async execute(input: string, context: DnsLookupContext = {}): Promise<ResolveTargetResult> {
    const value = input.trim();
    const host = (isTxtTarget(value) ? value.slice(TXT_TARGET_PREFIX.length) : value).trim().toLowerCase();
    if (!isDnsName(host)) return { ok: false, message: '请输入有效的域名' };
    return isTxtTarget(value) ? await this.resolveTxt(host, context) : await this.resolveAddresses(host, context);
  }

  private async resolveTxt(host: string, context: DnsLookupContext): Promise<ResolveTargetResult> {
    const result = await this.lookup.query(host, 'TXT', context);
    if (!result.ok) return { ok: false, message: `TXT 记录查询失败：${result.message}` };

    const addresses: string[] = [];
    const seen = new Set<string>();
    for (const value of result.values) {
      for (const address of parseTxtAddresses(value)) {
        if (seen.has(address)) continue;
        // TXT 里常混着 SPF、域名验证等文本；只保留 IP 或带点的域名。
        const target = parseProxyTarget(address, 443);
        if (!target) continue;
        if (target.family === 'hostname' && !target.host.includes('.')) continue;
        seen.add(address);
        addresses.push(address);
        if (addresses.length >= MAX_RESOLVED_ADDRESSES) break;
      }
    }
    if (addresses.length === 0) return { ok: false, message: `${host} 的 TXT 记录里没有可用的 IP 或域名` };
    return { ok: true, source: { kind: 'txt', host, addresses } };
  }

  private async resolveAddresses(host: string, context: DnsLookupContext): Promise<ResolveTargetResult> {
    const [ipv4, ipv6] = await Promise.all([
      this.lookup.query(host, 'A', context),
      this.lookup.query(host, 'AAAA', context),
    ]);
    if (!ipv4.ok && !ipv6.ok) {
      return { ok: false, message: `域名解析失败：${ipv4.ok ? ipv6.message : ipv4.message}` };
    }

    const addresses: string[] = [];
    const seen = new Set<string>();
    for (const result of [ipv4, ipv6]) {
      if (!result.ok) continue;
      for (const value of result.values) {
        if (seen.has(value)) continue;
        seen.add(value);
        addresses.push(value);
        if (addresses.length >= MAX_RESOLVED_ADDRESSES) break;
      }
    }
    if (addresses.length === 0) return { ok: false, message: `${host} 没有解析到 A/AAAA 记录` };
    return { ok: true, source: { kind: 'dns', host, addresses } };
  }
}
