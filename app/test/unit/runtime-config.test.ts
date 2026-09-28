import { describe, expect, it } from 'vitest';
import { CompositeProbeAdapter } from '../../src/adapters/probe/composite';
import type { SocketConnect } from '../../src/adapters/probe/socket';
import { createProbeAdapterFromConfig, loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, toProbeConfig, type ProbeConfig } from '../../src/contracts/config';
import { parseProxyTarget } from '../../src/domain/proxy-target';
import { alive, dead, unknown, type ProbeStatus } from '../../src/domain/probe-result';
import type { ProbeAdapter } from '../../src/ports/probe';

const target = parseProxyTarget('203.0.113.10:443');
if (!target) throw new Error('test target is invalid');

/** 只断言适配器选择时不需要真的建连，被调用即说明选择逻辑写错了。 */
const unusedConnect: SocketConnect = () => {
  throw new Error('socket connect should not be called while selecting an adapter');
};

function probeConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  return { ...toProbeConfig(createDefaultConfig()), ...overrides };
}

/** 只记录调用顺序并回放固定结论，用来断言级联判定顺序而不做真实网络访问。 */
function stubAdapter(name: string, status: ProbeStatus, calls: string[]): ProbeAdapter {
  return {
    name,
    async probe(probeTarget) {
      calls.push(name);
      const message = name === 'external' ? '外部复检接口超时' : '内部检测没有结论';
      const details = { message, ...(status === 'alive' ? { exitIp: '203.0.113.20', exitFamily: 'ipv4' as const } : {}) };
      if (status === 'unknown') return unknown(probeTarget, 'TIMEOUT', message, details);
      return { alive, dead }[status](probeTarget, details);
    },
  };
}

describe('runtime configuration', () => {
  it('builds cmliu check URLs and clamps timeout', () => {
    const config = loadEnvConfig({
      PROBE_MODE: 'cmliu-check',
      CHECK_API: 'https://probe.example/base',
      CHECK_TIMEOUT: '10',
    });

    expect(config.settings.CHECK_TIMEOUT).toBe(500);
    expect(toProbeConfig(config).endpoints[0]?.urlTemplate).toBe('https://probe.example/base/check?proxyip={proxyip}');
  });

  it('ignores invalid cmliu URLs instead of crashing the Worker', () => {
    const config = loadEnvConfig({ PROBE_MODE: 'cmliu-check', CHECK_API: 'not a url', CHECK_API_BACKUP: '' });
    expect(toProbeConfig(config).endpoints).toEqual([]);
  });

  it('returns unknown instead of dead when no endpoint is configured', async () => {
    const defaults = createDefaultConfig();
    const adapter = createProbeAdapterFromConfig(toProbeConfig({ ...defaults, checkApi: '', checkApiBackup: '' }));

    await expect(adapter.probe(target)).resolves.toMatchObject({
      status: 'unknown',
      code: 'NOT_CONFIGURED',
    });
  });

  it('reads the dual probe URLs from the environment', () => {
    const config = loadEnvConfig({
      PROBE_MODE: 'socket',
      SOCKET_PROBE_IPV4_URL: ' https://ipv4.probe.example/check ',
      SOCKET_PROBE_IPV6_URL: 'https://ipv6.probe.example/check?x=1',
    });

    expect(config.probeMode).toBe('socket');
    expect(config.socketProbeIpv4Url).toBe('https://ipv4.probe.example/check');
    expect(config.socketProbeIpv6Url).toBe('https://ipv6.probe.example/check?x=1');
  });

  it('keeps the built-in probe URLs when the environment value is unusable', () => {
    const defaults = createDefaultConfig();
    const config = loadEnvConfig({
      PROBE_MODE: 'socket',
      SOCKET_PROBE_IPV4_URL: 'http://plain.example/',
      SOCKET_PROBE_IPV6_URL: '   ',
    });

    // 非法地址与留白都退回默认探针；要停用某一族应写进面板配置而不是环境变量。
    expect(config.socketProbeIpv4Url).toBe(defaults.socketProbeIpv4Url);
    expect(config.socketProbeIpv6Url).toBe(defaults.socketProbeIpv6Url);
  });

  it('falls back to the external API probe for an unknown mode', () => {
    expect(loadEnvConfig({ PROBE_MODE: 'socket-typo' }).probeMode).toBe('external-api');
  });

  it('selects the socket adapter only when connect and a probe URL are available', () => {
    expect(createProbeAdapterFromConfig(probeConfig({ primary: 'internal', endpoints: [] }), { connect: unusedConnect }).name).toBe(
      'socket',
    );
    // 缺少 connect 属于部署错误：只剩外部复检可用时退回单链路，一条都没有才是"未配置"。
    expect(createProbeAdapterFromConfig(probeConfig({ primary: 'internal' })).name).toBe('external-api');
    expect(
      createProbeAdapterFromConfig(probeConfig({ primary: 'internal', ipv4ProbeUrl: '', ipv6ProbeUrl: '', endpoints: [] })).name,
    ).toBe('unconfigured');
    expect(
      createProbeAdapterFromConfig(
        probeConfig({ primary: 'internal', ipv4ProbeUrl: '', ipv6ProbeUrl: '', endpoints: [] }),
        { connect: unusedConnect },
      ).name,
    ).toBe('unconfigured');
  });

  it('cascades the internal probe into the external recheck when both are configured', async () => {
    const calls: string[] = [];
    const internal = stubAdapter('internal', 'unknown', calls);
    const external = stubAdapter('external', 'alive', calls);
    const adapter = new CompositeProbeAdapter({ internal, external, primary: 'internal' });

    await expect(adapter.probe(target)).resolves.toMatchObject({ status: 'alive', exitIp: '203.0.113.20' });
    expect(calls).toEqual(['internal', 'external']);
  });

  it('keeps the primary result when it already proves the node is alive', async () => {
    const calls: string[] = [];
    const internal = stubAdapter('internal', 'alive', calls);
    const external = stubAdapter('external', 'dead', calls);
    const adapter = new CompositeProbeAdapter({ internal, external, primary: 'internal' });

    await expect(adapter.probe(target)).resolves.toMatchObject({ status: 'alive' });
    // 主链路已经能证明可用，就不再打外部接口，省一次子请求。
    expect(calls).toEqual(['internal']);
  });

  it('never upgrades two probe failures into dead', async () => {
    const calls: string[] = [];
    const internal = stubAdapter('internal', 'unknown', calls);
    const external = stubAdapter('external', 'unknown', calls);
    const adapter = new CompositeProbeAdapter({ internal, external, primary: 'internal' });

    const result = await adapter.probe(target);
    expect(result.status).toBe('unknown');
    expect(result.message).toContain('外部复检接口超时');
  });

  it('reports dead only when one trusted probe explicitly rejects the node', async () => {
    const calls: string[] = [];
    const internal = stubAdapter('internal', 'unknown', calls);
    const external = stubAdapter('external', 'dead', calls);
    const adapter = new CompositeProbeAdapter({ internal, external, primary: 'internal' });

    await expect(adapter.probe(target)).resolves.toMatchObject({ status: 'dead' });
  });

  it('builds a composite adapter when both the socket and the external probe are available', () => {
    const config = probeConfig({ primary: 'internal' });
    expect(config.endpoints.length).toBeGreaterThan(0);
    expect(createProbeAdapterFromConfig(config, { connect: unusedConnect }).name).toBe('composite');
    // 只留外部接口时退回单链路，不做无意义的级联。
    expect(createProbeAdapterFromConfig({ ...config, ipv4ProbeUrl: '', ipv6ProbeUrl: '' }).name).toBe('external-api');
  });
});
