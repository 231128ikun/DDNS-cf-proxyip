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
