import { asRecord } from '../../contracts/parse';

interface DiagnosticEndpoint {
  readonly urlTemplate: string;
  readonly headers?: Readonly<Record<string, string>>;
}

/** 仅保留可排查的短消息；接口凭据、URL 参数和资源 ID 不进入返回值或日志。 */
export function createProbeRedactor(endpoints: readonly DiagnosticEndpoint[]): (value: string) => string {
  const secrets: string[] = [];
  for (const endpoint of endpoints) {
    for (const value of Object.values(endpoint.headers ?? {})) {
      secrets.push(value, value.replace(/^Bearer\s+/i, ''));
    }
    try {
      const url = new URL(endpoint.urlTemplate);
      secrets.push(url.username, url.password);
      url.searchParams.forEach((value, key) => { if (/key|token|secret|password|auth/i.test(key)) secrets.push(value); });
      for (const value of url.pathname.split('/')) if (value && !value.includes('proxyip')) secrets.push(value);
    } catch { /* 无效接口 URL 由请求路径明确报错，不在这里输出原值。 */ }
  }
  const values = [...new Set(secrets.filter(Boolean).flatMap(value => {
    try { return [value, decodeURIComponent(value), encodeURIComponent(value), JSON.stringify(value).slice(1, -1)]; }
    catch { return [value]; }
  }))].sort((a, b) => b.length - a.length);
  return value => {
    let text = value;
    for (const secret of values) text = text.split(secret).join('[redacted]');
    text = text.replace(/https?:\/\/[^\s<>"']+/gi, raw => {
      try { return new URL(raw).origin; } catch { return '[url]'; }
    });
    return text.replace(/\bbody\s*[:=][\s\S]*$/i, '[response body omitted]')
      .replace(/\b(?:token|secret|password|authorization|cookie|auth[_-]?key|api[_-]?key|cf[_-]?(?:key|token)|tg[_-]?token)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,}]+)/gi, '[credential redacted]')
      .replace(/Bearer\s+[^\s,"']+/gi, 'Bearer [redacted]')
      .replace(/\b[a-f0-9]{32}\b/gi, '[resource-id]')
      .replace(/[\r\n\t]+/g, ' ').trim().slice(0, 240);
  };
}

export function probeErrorMessage(error: unknown): string {
  const parts: string[] = [];
  let current: unknown = error;
  for (let depth = 0; current && depth < 3; depth++) {
    const record = asRecord(current);
    if (!record) break;
    const name = typeof record.name === 'string' ? record.name : 'Error';
    const message = typeof record.message === 'string' ? record.message : '';
    const code = typeof record.code === 'string' ? record.code : '';
    parts.push([name, code, message].filter(Boolean).join(': '));
    current = record.cause;
  }
  return parts.join(' → ') || '未知请求错误';
}

const RESPONSE_FIELDS = new Set(['success', 'ok', 'apiError', 'status', 'error', 'message', 'detail', 'reason', 'code', 'data', 'probe_results', 'probeResults', 'probes', 'exits', 'exit', 'proxyIP']);

export function probeResponseShape(value: unknown): string {
  if (Array.isArray(value)) return 'array(' + value.length + ')';
  const record = asRecord(value);
  if (!record) return value === null ? 'null' : typeof value;
  const keys = Object.keys(record);
  return 'object(' + keys.length + ': ' + keys.filter(key => RESPONSE_FIELDS.has(key)).join(',') + ')';
}
