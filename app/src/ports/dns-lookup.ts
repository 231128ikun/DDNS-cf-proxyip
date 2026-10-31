/** 公共 DNS 查询（DoH）端口：只描述“要查什么”，不关心用什么协议实现。 */

export type DnsLookupType = 'A' | 'AAAA' | 'TXT';

export interface DnsLookupContext {
  readonly signal?: AbortSignal;
}

export type DnsLookupFailureCode =
  | 'ABORTED'
  | 'TIMEOUT'
  | 'NETWORK_ERROR'
  | 'HTTP_ERROR'
  | 'BAD_RESPONSE'
  | 'DNS_STATUS';

export type DnsLookupResult =
  | { readonly ok: true; readonly values: readonly string[] }
  | { readonly ok: false; readonly code: DnsLookupFailureCode; readonly message: string };

/**
 * 查询失败一律返回 `ok: false`，不抛异常：
 * 域名解析失败只能得到 unknown，不能把节点判成失效。
 */
export interface DnsLookup {
  query(name: string, type: DnsLookupType, context?: DnsLookupContext): Promise<DnsLookupResult>;
}
