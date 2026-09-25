import { describe, expect, it } from 'vitest';
import { exitFamilyFromIp, isProbeErrorResult, unknown } from '../../src/domain/probe-result';

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
    expect(isProbeErrorResult(unknown(null, 'TIMEOUT', 'timeout'))).toBe(true);
    expect(isProbeErrorResult(unknown(null, 'HTTP_ERROR', '500'))).toBe(true);
    expect(isProbeErrorResult(unknown(null, 'NOT_CONFIGURED', 'unset'))).toBe(true);
  });

  it('excludes placeholders that never reached the probe', () => {
    expect(isProbeErrorResult(unknown(null, 'NOT_PROBED', 'waiting'))).toBe(false);
    expect(isProbeErrorResult(unknown(null, 'INVALID_DNS_VALUE', 'bad record'))).toBe(false);
  });
});
