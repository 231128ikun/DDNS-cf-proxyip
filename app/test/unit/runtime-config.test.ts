import { describe, expect, it } from 'vitest';
import type { SocketConnect } from '../../src/adapters/probe/socket';
import { createProbeAdapterFromConfig, loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, toProbeConfig, type ProbeConfig } from '../../src/contracts/config';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = parseProxyTarget('203.0.113.10:443');
if (!target) throw new Error('test target is invalid');

/** 只断言适配器选择时不需要真的建连，被调用即说明选择逻辑写错了。 */
const unusedConnect: SocketConnect = () => {
  throw new Error('socket connect should not be called while selecting an adapter');
};

function probeConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  return { ...toProbeConfig(createDefaultConfig()), ...overrides };
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
    expect(createProbeAdapterFromConfig(probeConfig({ mode: 'socket' }), { connect: unusedConnect }).name).toBe('socket');
    // 缺少 connect 属于部署错误，必须退化成"未配置"而不是把节点判死。
    expect(createProbeAdapterFromConfig(probeConfig({ mode: 'socket' })).name).toBe('unconfigured');
    expect(
      createProbeAdapterFromConfig(probeConfig({ mode: 'socket', ipv4ProbeUrl: '', ipv6ProbeUrl: '' }), {
        connect: unusedConnect,
      }).name,
    ).toBe('unconfigured');
  });
});
