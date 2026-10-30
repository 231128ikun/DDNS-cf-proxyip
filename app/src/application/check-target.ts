import { parseRuntimeSetting } from '../contracts/runtime-settings';
import type { ProbeResult } from '../domain/probe-result';
import { parseProxyTarget } from '../domain/proxy-target';
import type { ProbeContext } from '../ports/probe';
import { mapWithConcurrency } from '../util/concurrency';
import type { CheckProxy } from './check-proxy';
import { isDnsName, isTxtTarget, type ResolveTarget, type ResolvedTargetSource } from './resolve-target';

/** 面板“探测”入口能接受的最大目标数，防止一个域名解析出过多地址打满子请求。 */
export const MAX_CHECK_TARGET_ITEMS = 50;

export type CheckTargetSource = { readonly kind: 'direct' } | ResolvedTargetSource;

export interface CheckTargetItem {
  /** 规范化后的地址（含端口），可直接用于入库。 */
  readonly address: string;
  readonly result: ProbeResult;
}

export interface CheckTargetReport {
  readonly input: string;
  readonly source: CheckTargetSource;
  readonly items: readonly CheckTargetItem[];
  /** 解析结果里无法识别的地址，原样回传便于用户排查。 */
  readonly skipped: readonly string[];
}

export type CheckTargetOutcome =
  | { readonly ok: true; readonly report: CheckTargetReport }
  | { readonly ok: false; readonly message: string };

export interface CheckTargetDependencies {
  readonly resolver: ResolveTarget;
  readonly checkProxy: CheckProxy;
  readonly concurrency?: number;
}

/**
 * 探测一个目标：
 * - `txt@域名` 取 TXT 里的地址列表；
 * - 裸域名先解析 A/AAAA；
 * - 带端口的域名和 IP 按字面目标处理。
 * 解析或探测失败只返回失败结果，不会把节点判成失效。
 */
export class CheckTarget {
  private readonly concurrency: number;

  constructor(private readonly dependencies: CheckTargetDependencies) {
    this.concurrency = parseRuntimeSetting('CONCURRENT_CHECKS', dependencies.concurrency);
  }

  async execute(input: string, context: ProbeContext = {}): Promise<CheckTargetOutcome> {
    const value = input.trim();
    if (needsDnsResolution(value)) {
      const resolved = await this.dependencies.resolver.execute(value, context);
      if (!resolved.ok) return resolved;
      return await this.probeAll(value, resolved.source, context);
    }

    const target = parseProxyTarget(value, 443);
    if (!target) return { ok: false, message: '请输入有效的 IP、域名和可选端口' };
    const result = await this.dependencies.checkProxy.execute(target.authority, context);
    return {
      ok: true,
      report: { input: value, source: { kind: 'direct' }, items: [{ address: target.authority, result }], skipped: [] },
    };
  }

  private async probeAll(
    input: string,
    source: ResolvedTargetSource,
    context: ProbeContext,
  ): Promise<CheckTargetOutcome> {
    const targets: string[] = [];
    const skipped: string[] = [];
    const seen = new Set<string>();
    for (const address of source.addresses) {
      const target = parseProxyTarget(address, 443);
      if (!target) {
        skipped.push(address);
        continue;
      }
      if (seen.has(target.key)) continue;
      seen.add(target.key);
      targets.push(target.authority);
      if (targets.length >= MAX_CHECK_TARGET_ITEMS) break;
    }
    if (targets.length === 0) return { ok: false, message: '解析结果里没有可探测的地址' };

    const items = await mapWithConcurrency(targets, this.concurrency, async (address): Promise<CheckTargetItem> => ({
      address,
      result: await this.dependencies.checkProxy.execute(address, context),
    }));
    return { ok: true, report: { input, source, items, skipped } };
  }
}

/**
 * 只有"看起来是域名、又没有显式端口"的输入才做 DNS 解析：
 * IP 字面量、URL、`example.com:8443` 都按字面目标探测。
 */
function needsDnsResolution(input: string): boolean {
  const value = input.trim();
  if (!value || value.length > 253) return false;
  if (isTxtTarget(value)) return true;
  if (/^https?:\/\//i.test(value)) return false;

  const family = parseProxyTarget(value, 443)?.family;
  if (family === 'ipv4' || family === 'ipv6') return false;
  if (hasExplicitPort(value)) return false;
  return isDnsName(value);
}

function hasExplicitPort(value: string): boolean {
  if (/^\[[^\]]+\]:\d{1,5}$/.test(value)) return true;
  const lastColon = value.lastIndexOf(':');
  return lastColon !== -1 && /^\d{1,5}$/.test(value.slice(lastColon + 1).trim());
}