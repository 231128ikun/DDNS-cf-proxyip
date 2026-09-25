/**
 * 北京时间格式化：KV 垃圾桶和通知文案共用，避免同一条规则出现两份实现。
 * 只保留到秒，且固定 `Asia/Shanghai`，不受 Worker 运行时区影响。
 */
export function formatBeijingTimestamp(date: Date): string {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}