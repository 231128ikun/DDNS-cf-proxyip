import type { Notifier, NotifyResult } from '../../ports/notifier';

export interface TelegramNotifierOptions {
  readonly enabled: boolean;
  readonly token: string;
  readonly chatId: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

/** Telegram Bot API adapter：只负责发送文本，通知条件与文案由 job / 消息模块决定。 */
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
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async send(text: string): Promise<NotifyResult> {
    if (!this.enabled) return { sent: false, reason: 'disabled' };
    if (!this.token || !this.chatId) return { sent: false, reason: 'not_configured' };

    try {
      const response = await this.fetchImpl(`https://api.telegram.org/bot${this.token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: this.chatId,
          text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      return response.ok ? { sent: true, reason: 'sent' } : { sent: false, reason: 'failed' };
    } catch {
      return { sent: false, reason: 'failed' };
    }
  }
}