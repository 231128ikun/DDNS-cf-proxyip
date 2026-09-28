import { unknown, type ExitFamily, type ProbeResult } from '../../domain/probe-result';
import type { ProxyTarget } from '../../domain/proxy-target';
import type { ProbeAdapter, ProbeContext } from '../../ports/probe';
import { uniqueExits } from './probe-payload';

export interface CompositeProbeOptions {
  /** 主检测链路：先跑，只有它没能证明节点可用时才触发复检。 */
  readonly internal: ProbeAdapter;
  /** 复检链路：外部接口，用于补齐或推翻主检测的结论。 */
  readonly external: ProbeAdapter;
  readonly primary: 'internal' | 'external';
}

/**
 * 内部 socket 探针 + 外部复检接口的级联判定。
 *
 * 判定顺序同时决定子请求数量：主链路报 `alive` 就直接结束，不再打外部接口。
 * 只有主链路没能证明可用时才走复检；两条链路都没能证明可用时，
 * 只要有一条明确拒绝就记 `dead`，全部是超时/网络/响应异常则一律 `unknown`，
 * 不会因为外部接口临时抽风就把节点误判为失效。
 */
export class CompositeProbeAdapter implements ProbeAdapter {
  readonly name = 'composite';

  private readonly internal: ProbeAdapter;
  private readonly external: ProbeAdapter;
  private readonly primary: 'internal' | 'external';

  constructor(options: CompositeProbeOptions) {
    this.internal = options.internal;
    this.external = options.external;
    this.primary = options.primary;
  }

  async probe(target: ProxyTarget, context: ProbeContext = {}): Promise<ProbeResult> {
    const first = this.primary === 'internal' ? this.internal : this.external;
    const second = this.primary === 'internal' ? this.external : this.internal;

    const primary = await first.probe(target, context);
    if (primary.status === 'alive' || context.signal?.aborted) return primary;

    const recheck = await second.probe(target, context);
    return combine(primary, recheck);
  }
}

function combine(primary: ProbeResult, recheck: ProbeResult): ProbeResult {
  const exits = uniqueExits([...primary.exits, ...recheck.exits]);
  const recheckAlive = recheck.status === 'alive';
  const exitIp = recheckAlive ? recheck.exitIp ?? primary.exitIp : primary.exitIp;
  const target = primary.target ?? recheck.target;
  const shared = {
    exitFamily: (recheckAlive ? recheck.exitFamily : primary.exitFamily) as ExitFamily,
    exits,
    ...(exitIp ? { exitIp } : {}),
    ...(recheck.latencyMs === undefined ? {} : { latencyMs: recheck.latencyMs }),
  };

  if (recheckAlive) return { ...recheck, ...shared };
  if (primary.status === 'dead') return { ...primary, ...shared };
  if (recheck.status === 'dead') return { ...recheck, ...shared };

  // 两条链路都只给出异常信息：保留 unknown，绝不因为复检失败升级成 dead。
  const details = [primary.message, recheck.message].filter((value): value is string => Boolean(value));
  return unknown(
    target,
    primary.code ?? recheck.code ?? 'UNKNOWN',
    details.length ? details.join('；') : '内部检测与外部复检都没有返回可用结论',
    { ...shared, ...(primary.endpoint ? { endpoint: primary.endpoint } : {}) },
  );
}
