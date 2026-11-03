import { expect, it } from 'vitest';
import { formatProbeLog } from '../../web/src/components/probe-log';
import { createProbeRedactor } from '../../src/adapters/probe/diagnostics';

it('includes the endpoint, error code and concrete reason in plain probe logs', () => {
  expect(formatProbeLog({ status: 'unknown', endpoint: 'backup', code: 'NETWORK_ERROR', message: 'ECONNRESET' }))
    .toContain('接口 backup [NETWORK_ERROR] · ECONNRESET');
});

it('keeps the failed primary attempt visible after backup recovery', () => {
  const message = formatProbeLog({ status: 'alive', endpoint: 'backup', diagnostics: [
    { endpoint: 'primary', status: 'unknown', code: 'HTTP_ERROR', message: '检测接口 HTTP 503' },
  ] });
  expect(message).toContain('可用');
  expect(message).toContain('最终接口 backup');
  expect(message).toContain('primary [HTTP_ERROR] 检测接口 HTTP 503');
});

it('redacts quoted credentials and does not print embedded raw response bodies', () => {
  const redact = createProbeRedactor([]);
  const output = redact('TLS failed {"api_key":"private key value","Authorization":"Basic private-auth"} body: <html>private-body</html>');
  for (const value of ['private key value', 'private-auth', 'private-body']) expect(output).not.toContain(value);
  expect(output).toContain('TLS failed');
});

it('prints complete DNS addresses but omits ordinary successful probe progress', async () => {
  const { formatDnsSnapshot, shouldLogProbe } = await import('../../web/src/components/probe-log');
  const text = formatDnsSnapshot({ ok: true, domain: 'edge.example.com', mode: 'A', records: [
    { id: 'a', type: 'A', name: 'edge.example.com', content: '203.0.113.10' },
    { id: 'aaaa', type: 'AAAA', name: 'edge.example.com', content: '2001:db8::10' },
  ] });
  expect(text).toContain('A 203.0.113.10');
  expect(text).toContain('AAAA 2001:db8::10');
  expect(shouldLogProbe({ status: 'alive' })).toBe(false);
  expect(shouldLogProbe({ status: 'unknown', code: 'HTTP_ERROR' })).toBe(true);
  expect(shouldLogProbe({ status: 'alive', diagnostics: [{ endpoint: 'primary', status: 'unknown', code: 'HTTP_ERROR', message: 'HTTP 503' }] })).toBe(true);
});
