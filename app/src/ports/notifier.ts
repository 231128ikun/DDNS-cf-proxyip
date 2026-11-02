export type NotifyReason = 'sent' | 'disabled' | 'not_configured' | 'failed';

export interface NotifyResult {
  readonly sent: boolean;
  readonly reason: NotifyReason;
}

export interface Notifier {
  send(text: string): Promise<NotifyResult>;
}