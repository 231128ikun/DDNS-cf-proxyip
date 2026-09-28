import type { ProbeConfig } from '../contracts/config';
import type { ProbeResult } from '../domain/probe-result';
import type { ProxyTarget } from '../domain/proxy-target';

export interface ProbeContext {
  readonly signal?: AbortSignal;
}

export interface ProbeAdapter {
  readonly name: string;
  probe(target: ProxyTarget, context?: ProbeContext): Promise<ProbeResult>;
}

/**
 * 用例层只描述“要什么样的探针”，具体实例化留给 `config/runtime.ts`。
 * 这样级联判定、接口自检等业务编排都不需要知道 sockets 或 fetch 的存在。
 */
export type ProbeAdapterFactory = (config: ProbeConfig) => ProbeAdapter;
