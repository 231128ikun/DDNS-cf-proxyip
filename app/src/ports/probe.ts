import type { ProbeResult } from '../domain/probe-result';
import type { ProxyTarget } from '../domain/proxy-target';

export interface ProbeContext {
  readonly signal?: AbortSignal;
  /** 同一逻辑检测共享连接收尾状态；分组检测为每个地址传入独立对象。 */
  readonly scope?: object;
}

export interface ProbeAdapter {
  readonly name: string;
  probe(target: ProxyTarget, context?: ProbeContext): Promise<ProbeResult>;
}
