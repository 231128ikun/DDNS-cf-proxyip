export function createPublicTextRedactor(secrets: readonly string[], limit = 240): (value: string) => string {
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
      .replace(/[\r\n\t]+/g, ' ').trim().slice(0, limit);
  };
}
