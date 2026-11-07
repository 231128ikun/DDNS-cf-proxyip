import { parseProxyTarget } from '../../src/domain/proxy-target';
import { describe, expect, it } from 'vitest';
import { dead, exitFamilyFromIp, isProbeErrorResult, unknown } from '../../src/domain/probe-result';

describe('exitFamilyFromIp', () => {
  it('detects IPv4', () => {
    expect(exitFamilyFromIp('203.0.113.8')).toBe('ipv4');
  });

  it('detects IPv6', () => {
    expect(exitFamilyFromIp('2001:db8::1')).toBe('ipv6');
  });

  it('rejects invalid IPv4 values', () => {
    expect(exitFamilyFromIp('999.1.1.1')).toBe('unknown');
  });
});

describe('isProbeErrorResult', () => {
  it('treats unknown probe outcomes as detection failures', () => {
    expect(isProbeErrorResult(unknown(null, 'NETWORK_ERROR', 'network error'))).toBe(true);
    expect(isProbeErrorResult(unknown(null, 'HTTP_ERROR', '500'))).toBe(true);
    expect(isProbeErrorResult(unknown(null, 'NOT_CONFIGURED', 'unset'))).toBe(true);
  });

  it('counts a partial exit anomaly without changing its alive status', () => {
    const result = { status: 'alive' as const, code: 'PARTIAL_EXIT' };
    expect(isProbeErrorResult(result)).toBe(true);
    expect(result.status).toBe('alive');
    expect(isProbeErrorResult({ status: 'alive' })).toBe(false);
  });

  it('excludes placeholders that never reached the probe', () => {
    expect(isProbeErrorResult(unknown(null, 'NOT_PROBED', 'waiting'))).toBe(false);
    expect(isProbeErrorResult(unknown(null, 'INVALID_DNS_VALUE', 'bad record'))).toBe(false);
  });
});


it('does not count a dead timeout result as a probe error', () => {
  const target = parseProxyTarget('203.0.113.10:443');
  if (!target) throw new Error('invalid fixture target');
  expect(isProbeErrorResult(dead(target, { code: 'TIMEOUT', message: '节点连接超时' }))).toBe(false);
});
