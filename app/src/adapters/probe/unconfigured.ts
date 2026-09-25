import { unknown, type ProbeResult } from '../../domain/probe-result';
import type { ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter } from '../../ports/probe';

export class UnconfiguredProbeAdapter implements ProbeAdapter {
  readonly name = 'unconfigured';

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    return unknown(target, 'NOT_CONFIGURED', '未配置检测接口');
  }
}