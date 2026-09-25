/** 通知端口：业务层只决定“要不要发、发什么文本”，渠道细节留在 adapter。 */
export type NotifyReason = 'sent' | 'disabled' | 'not_configured' | 'failed';

export interface NotifyResult {
  readonly sent: boolean;
  readonly reason: NotifyReason;
}

export interface Notifier {
  send(text: string): Promise<NotifyResult>;
}