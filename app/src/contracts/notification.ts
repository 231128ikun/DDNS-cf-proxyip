export type NotifyReason = 'sent' | 'disabled' | 'not_configured' | 'failed';

/** 发送状态不携带凭据或原始响应。分段发送只有全部成功才记为 sent。 */
export interface NotifyResult {
  readonly sent: boolean;
  readonly reason: NotifyReason;
  readonly delivered?: number;
  readonly total?: number;
  readonly code?: string;
}
