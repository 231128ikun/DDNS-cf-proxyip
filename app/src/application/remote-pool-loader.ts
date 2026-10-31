import { cleanPoolText } from '../domain/pool-text';
import type { RemotePoolSource, RemoteLoadRequestOptions, RemotePoolLoadResult } from '../ports/remote-pool-source';

/** 网络和响应体处理由端口完成；用例只应用统一的池文本规则。 */
export class RemotePoolLoader {
  constructor(private readonly source: RemotePoolSource) {}

  async load(rawUrl: string, options: RemoteLoadRequestOptions = {}): Promise<RemotePoolLoadResult> {
    const result = await this.source.load(rawUrl, options);
    return result.ok ? { ...result, content: cleanPoolText(result.content) } : result;
  }
}
