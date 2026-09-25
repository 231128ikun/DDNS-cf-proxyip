import type { ProbeResult } from '../domain/probe-result';
import type { ProxyTarget } from '../domain/proxy-target';

export interface ProbeContext {
  readonly signal?: AbortSignal;
}

export interface ProbeAdapter {
  readonly name: string;
  probe(target: ProxyTarget, context?: ProbeContext): Promise<ProbeResult>;
}