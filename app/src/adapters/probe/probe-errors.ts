/** 已确认的平台异常；不使用普通网络、TLS、限流文案猜测节点状态。 */
export function isTcpLoop(message: string): boolean {
  return /\btcp loop detected\b/i.test(message);
}
