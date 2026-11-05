import type { Notifier, NotifyResult } from '../../ports/notifier';
import { asRecord } from '../../contracts/parse';
import { appFetch } from '../../util/fetch';

export interface TelegramNotifierOptions {
  readonly enabled: boolean;
  readonly token: string;
  readonly chatId: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

/** 维护模板每行独立闭合 HTML，按完整行分段，不截断地址、标签或实体。 */
function messageParts(text: string): string[] | null {
  const limit = 3500;
  const parts: string[] = [];
  let current: string[] = [];
  let length = 0;
  for (const line of text.split('\n')) {
    if (line.length > limit) return null;
    const next = length + (current.length ? 1 : 0) + line.length;
    if (next > limit) { parts.push(current.join('\n')); current = [line]; length = line.length; }
    else { current.push(line); length = next; }
  }
  if (current.length) parts.push(current.join('\n'));
  return parts;
}

export class TelegramNotifier implements Notifier {
  private readonly enabled: boolean;
  private readonly token: string;
  private readonly chatId: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: TelegramNotifierOptions) {
    this.enabled = options.enabled;
    this.token = options.token.trim();
    this.chatId = options.chatId.trim();
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchImpl = options.fetchImpl ?? appFetch;
  }

  async send(text: string): Promise<NotifyResult> {
    if (!this.enabled) return { sent: false, reason: 'disabled' };
    if (!this.token || !this.chatId) return { sent: false, reason: 'not_configured' };
    const parts = messageParts(text);
    if (!parts?.length) return { sent: false, reason: 'failed', code: 'MESSAGE_TOO_LONG', delivered: 0, total: 0 };
    let delivered = 0;
    const failed = (code: string): NotifyResult => ({ sent: false, reason: 'failed', code, delivered, total: parts.length });
    for (const part of parts) {
      try {
        const response = await this.fetchImpl(`https://api.telegram.org/bot${this.token}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: this.chatId, text: part, parse_mode: 'HTML', disable_web_page_preview: true }),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (!response.ok) {
          await response.body?.cancel().catch(() => undefined);
          return failed('HTTP_' + response.status);
        }
        let data;
        try { data = asRecord(await response.json()); }
        catch (error) { if (error instanceof SyntaxError) return failed('INVALID_RESPONSE'); throw error; }
        if (data?.ok !== true) return failed(typeof data?.error_code === 'number' ? 'TELEGRAM_' + data.error_code : 'INVALID_RESPONSE');
        delivered++;
      } catch (error) {
        return failed(error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name) ? 'TIMEOUT' : 'NETWORK_ERROR');
      }
    }
    return parts.length === 1 ? { sent: true, reason: 'sent' } : { sent: true, reason: 'sent', delivered, total: parts.length };
  }
}
