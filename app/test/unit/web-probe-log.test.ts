import { expect, it, vi } from 'vitest';
import { logProbe } from '../../web/src/components/probe-log';
import { createProbeRedactor } from '../../src/adapters/probe/diagnostics';

it('includes the endpoint, error code and concrete reason in plain probe logs', () => {
  const log = vi.fn();
  logProbe(log, '检测', '203.0.113.10:443', { status: 'unknown', endpoint: 'backup', code: 'NETWORK_ERROR', message: 'ECONNRESET' });
  expect(log).toHaveBeenCalledWith('[检测] 203.0.113.10:443 · 未知 · 检测接口异常', 'warning', '接口 backup [NETWORK_ERROR] · ECONNRESET');
});

it('keeps the failed primary attempt visible after backup recovery', () => {
  const log = vi.fn();
  logProbe(log, '检测', '203.0.113.10:443', { status: 'alive', endpoint: 'backup', diagnostics: [
    { endpoint: 'primary', status: 'unknown', code: 'HTTP_ERROR', message: '检测接口 HTTP 503' },
  ] });
  expect(log).toHaveBeenCalledWith('[检测] 203.0.113.10:443 · 可用 · 含复检记录', 'warning', '最终接口 backup · primary [HTTP_ERROR] 检测接口 HTTP 503');
});

it('redacts quoted credentials and does not print embedded raw response bodies', () => {
  const redact = createProbeRedactor([]);
  const output = redact('TLS failed {"api_key":"private key value","Authorization":"Basic private-auth"} body: <html>private-body</html>');
  for (const value of ['private key value', 'private-auth', 'private-body']) expect(output).not.toContain(value);
  expect(output).toContain('TLS failed');
});

it('formats live successful checks and retains partial-exit warnings', () => {
  const log = vi.fn();
  logProbe(log, '检测', '203.0.113.10:443', { status: 'alive', latencyMs: 12, colo: 'ICN', country: 'KR' });
  logProbe(log, '检测', '203.0.113.10:443', { status: 'alive', code: 'PARTIAL_EXIT', message: 'IPv6 检测异常' });
  expect(log).toHaveBeenNthCalledWith(1, '[检测] 203.0.113.10:443 · 可用 · 12ms · ICN · KR', 'success', undefined);
  expect(log).toHaveBeenNthCalledWith(2, '[检测] 203.0.113.10:443 · 可用 · 部分出口异常', 'success', '[PARTIAL_EXIT] · IPv6 检测异常');
});
