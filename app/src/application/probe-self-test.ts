import { toProbeConfig, type AppConfig, type ProbeConfig } from '../contracts/config';
import { PROBE_TEST_ITEM_IDS, type ProbeTestDraft, type ProbeTestItemId } from '../contracts/probe';
import type { ProbeResult } from '../domain/probe-result';
import { parseProxyTarget, type ProxyTarget } from '../domain/proxy-target';
import type { ProbeAdapterFactory, ProbeContext } from '../ports/probe';

export interface ProbeSelfTestInput {
  readonly proxyip: string;
  /** 已保存的配置；草稿里出现过的字段优先，没出现的沿用这里的值。 */
  readonly config: AppConfig;
  readonly draft?: ProbeTestDraft;
}

export interface ProbeSelfTestItem {
  readonly id: ProbeTestItemId;
  readonly label: string;
  readonly configured: boolean;
  readonly result?: ProbeResult;
  readonly error?: string;
}

export interface ProbeSelfTestResult {
  readonly proxyip: string;
  readonly items: readonly ProbeSelfTestItem[];
}

interface SelfTestItem {
  readonly id: ProbeTestItemId;
  readonly label: string;
  readonly isConfigured: (config: AppConfig) => boolean;
  /** 每条链路单独成一份探针配置，这样自检看到的就是这一条链路本身的结果。 */
  readonly probeConfig: (base: ProbeConfig) => ProbeConfig;
}

const SELF_TEST_ITEMS: readonly SelfTestItem[] = [
  {
    id: 'internal-ipv4',
    label: '内部检测 · IPv4',
    isConfigured: (config) => config.socketProbeIpv4Url.trim().length > 0,
    probeConfig: (base) => ({ ...base, endpoints: [], ipv6ProbeUrl: '' }),
  },
  {
    id: 'internal-ipv6',
    label: '内部检测 · IPv6',
    isConfigured: (config) => config.socketProbeIpv6Url.trim().length > 0,
    probeConfig: (base) => ({ ...base, endpoints: [], ipv4ProbeUrl: '' }),
  },
  {
    id: 'external-primary',
    label: '外部复检 · 主接口',
    isConfigured: (config) => config.checkApi.trim().length > 0,
    probeConfig: (base) => ({
      ...base,
      ipv4ProbeUrl: '',
      ipv6ProbeUrl: '',
      fallbackToNext: false,
      endpoints: [{ name: 'primary', urlTemplate: base.endpoints[0]?.urlTemplate ?? '' }],
    }),
  },
  {
    id: 'external-backup',
    label: '外部复检 · 备用接口',
    isConfigured: (config) => config.checkApiBackup.trim().length > 0,
    probeConfig: (base) => ({
      ...base,
      ipv4ProbeUrl: '',
      ipv6ProbeUrl: '',
      fallbackToNext: false,
      endpoints: [{ name: 'backup', urlTemplate: base.endpoints[1]?.urlTemplate ?? '' }],
    }),
  },
];

const SELF_TEST_ITEM_BY_ID: Readonly<Record<ProbeTestItemId, SelfTestItem>> = Object.fromEntries(
  SELF_TEST_ITEMS.map((item) => [item.id, item]),
) as Record<ProbeTestItemId, SelfTestItem>;

/**
 * 配置中心的接口自检。
 *
 * 语义上刻意区别于 `/api/check`：那边回答「这条节点到底能不能用」，
 * 这里回答「我刚填的每一条探针链路各自通不通」。所以逐条给结论，
 * 未配置的链路标为未配置，而不是伪装成一次失败；四条链路互不影响，
 * 一条超时不会污染其余三条的判断。
 */
export class ProbeSelfTest {
  constructor(private readonly createAdapter: ProbeAdapterFactory) {}

  async execute(input: ProbeSelfTestInput, context: ProbeContext = {}): Promise<ProbeSelfTestResult> {
    const effective = applyDraft(input.config, input.draft);
    const target = parseProxyTarget(input.proxyip);
    if (!target) {
      const error = '请输入有效的 IP、域名和可选端口';
      return {
        proxyip: input.proxyip,
        items: SELF_TEST_ITEMS.map((item) => ({ id: item.id, label: item.label, configured: false, error })),
      };
    }

    const base = toProbeConfig(effective);
    const items = await Promise.all(
      PROBE_TEST_ITEM_IDS.map((id) => this.runItem(SELF_TEST_ITEM_BY_ID[id], effective, base, target, context)),
    );
    return { proxyip: input.proxyip, items };
  }

  private async runItem(
    item: SelfTestItem,
    effective: AppConfig,
    base: ProbeConfig,
    target: ProxyTarget,
    context: ProbeContext,
  ): Promise<ProbeSelfTestItem> {
    if (!item.isConfigured(effective)) {
      return { id: item.id, label: item.label, configured: false };
    }

    try {
      const adapter = this.createAdapter(item.probeConfig(base));
      return { id: item.id, label: item.label, configured: true, result: await adapter.probe(target, context) };
    } catch (error) {
      return {
        id: item.id,
        label: item.label,
        configured: true,
        error: error instanceof Error ? error.message : '探针执行失败',
      };
    }
  }
}

function applyDraft(config: AppConfig, draft: ProbeTestDraft | undefined): AppConfig {
  if (!draft) return config;
  return {
    ...config,
    ...(draft.probeMode === undefined ? {} : { probeMode: draft.probeMode }),
    ...(draft.checkApi === undefined ? {} : { checkApi: draft.checkApi }),
    ...(draft.checkApiBackup === undefined ? {} : { checkApiBackup: draft.checkApiBackup }),
    ...(draft.socketProbeIpv4Url === undefined ? {} : { socketProbeIpv4Url: draft.socketProbeIpv4Url }),
    ...(draft.socketProbeIpv6Url === undefined ? {} : { socketProbeIpv6Url: draft.socketProbeIpv6Url }),
    ...(draft.socketReadLimitBytes === undefined ? {} : { socketReadLimitBytes: draft.socketReadLimitBytes }),
  };
}
