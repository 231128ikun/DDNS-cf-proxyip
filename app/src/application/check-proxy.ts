import { unknown, type ProbeResult } from '../domain/probe-result';
import { parseProxyTarget } from '../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../ports/probe';

export class CheckProxy {
  constructor(private readonly probeAdapter: ProbeAdapter) {}

  async execute(input: string, context: ProbeContext = {}): Promise<ProbeResult> {
    const target = parseProxyTarget(input);
    if (!target) {
      return unknown(null, 'INVALID_TARGET', '请输入有效的 IP、域名和可选端口');
    }
    return this.probeAdapter.probe(target, context);
  }
}