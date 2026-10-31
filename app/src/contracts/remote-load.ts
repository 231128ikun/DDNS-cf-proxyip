/** 远程 IP 池加载接口的请求/响应契约。 */

export interface RemoteLoadRequest {
  readonly url: string;
}

export interface RemoteLoadResponse {
  /** 重定向后的最终地址，便于确认实际读取的是哪个文件。 */
  readonly url: string;
  readonly content: string;
  readonly count: number;
}