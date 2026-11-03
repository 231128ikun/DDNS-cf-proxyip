import type { NotifyResult } from '../contracts/notification';
export type { NotifyReason, NotifyResult } from '../contracts/notification';

export interface Notifier {
  send(text: string): Promise<NotifyResult>;
}