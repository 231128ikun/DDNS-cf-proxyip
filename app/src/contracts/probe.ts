import type { ProbeResult } from '../domain/probe-result';
import { parseProxyTarget } from '../domain/proxy-target';
import { readJsonStream } from './json-stream';
import { isRecord, parseFail, parseOk, readTrimmedString, type ParseResult } from './parse';

export const MAX_PROXYIP_LENGTH = 512;
/** 父请求加最多八个内部检测调用，低于单请求 32 次 Worker 调用上限。 */
export const MAX_CHECK_BATCH_SIZE = 8;

/** 单目标保留域名解析；分组只接收 IP，防止组内再次展开目标。 */
export function parseCheckProxyInput(value: unknown): ParseResult<string | readonly string[]> {
  if (Array.isArray(value)) {
    if (!value.length || value.length > MAX_CHECK_BATCH_SIZE) return parseFail('检测分组超出地址数量限制');
    const addresses: string[] = [];
    const seen = new Set<string>();
    for (const item of value) {
      const text = readTrimmedString(item, 1, MAX_PROXYIP_LENGTH);
      const target = text ? parseProxyTarget(text, 443) : null;
      if (!target || target.family === 'hostname' || seen.has(target.key)) return parseFail('检测分组必须包含互不重复的 IP 地址');
      seen.add(target.key);
      addresses.push(target.authority);
    }
    return parseOk(addresses);
  }
  const proxyip = readTrimmedString(value, 1, MAX_PROXYIP_LENGTH);
  if (!proxyip) return parseFail(`proxyip must be 1-${MAX_PROXYIP_LENGTH} characters`);
  return parseOk(proxyip);
}

export type ProbeResponse = Omit<ProbeResult, 'target'> & { readonly executionColo?: string };

/** 浏览器和写入边界共用检测结果校验。 */
export function isProbeResponse(value: unknown): value is ProbeResponse {
  if (!isRecord(value) || typeof value.status !== 'string' || !['alive', 'dead', 'unknown'].includes(value.status)
    || typeof value.exitFamily !== 'string' || !['ipv4', 'ipv6', 'dual', 'unknown'].includes(value.exitFamily)) return false;
  return Array.isArray(value.exits) && value.exits.every(exit => isRecord(exit)
    && ['ip', 'asn', 'country', 'region', 'city'].every(key => exit[key] === undefined || typeof exit[key] === 'string'));
}

/** 探测入口的解析来源：direct 表示输入本身就是目标，txt/dns 表示先解析出地址再探测。 */
export interface CheckTargetSourceResponse {
  readonly kind: 'direct' | 'txt' | 'dns';
  readonly host?: string;
  readonly addresses?: readonly string[];
}

export interface CheckTargetItemResponse {
  /** 规范化后的地址（含端口）。 */
  readonly address: string;
  readonly result: ProbeResponse;
}

/** `POST /api/check` 的响应：一个输入可能对应多个地址。 */
export interface CheckTargetResponse {
  readonly ok: true;
  readonly input: string;
  readonly source: CheckTargetSourceResponse;
  readonly items: readonly CheckTargetItemResponse[];
  readonly skipped: readonly string[];
}
export function isCheckTargetItemResponse(value: unknown): value is CheckTargetItemResponse {
  return isRecord(value) && typeof value.address === 'string' && Boolean(parseProxyTarget(value.address, 443)) && isProbeResponse(value.result);
}

export async function readCheckStreamResult(
  read: () => Promise<{ done: boolean; value?: Uint8Array | undefined }>,
  onItem: (item: CheckTargetItemResponse) => void,
): Promise<CheckTargetResponse> {
  const result = await readJsonStream<CheckTargetResponse>(read, event => {
    if (!isRecord(event)) throw new SyntaxError('检测响应格式无效');
    if (event.type === 'progress') onItem(event.item as CheckTargetItemResponse);
    else if (event.type === 'result' && isRecord(event.result)) return event.result as unknown as CheckTargetResponse;
    else if (event.type === 'error' && typeof event.message === 'string') throw new Error(event.message);
    else throw new SyntaxError('检测响应格式无效');
    return undefined;
  });
  if (!result) throw new Error('检测响应提前结束');
  return result;
}

export type ConfigSource = 'kv' | 'env';

export interface HealthResponse {
  readonly ok: true;
  readonly version: string;
  readonly configSource?: ConfigSource;
  readonly executionColo?: string;
}

export interface ApiErrorResponse {
  readonly error: string;
}
