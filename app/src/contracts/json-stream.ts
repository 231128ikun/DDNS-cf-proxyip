export const JSON_STREAM_TYPE = 'application/x-ndjson';

/** 分帧与 UTF-8 解码共用，事件校验留给各接口契约。 */
export async function readJsonStream<Result>(
  read: () => Promise<{ done: boolean; value?: Uint8Array | undefined }>,
  accept: (event: unknown) => Result | undefined,
): Promise<Result | undefined> {
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await read();
    buffer += decoder.decode(value, { stream: !done });
    if (done && buffer.trim()) buffer += '\n';
    let end: number;
    while ((end = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, end);
      buffer = buffer.slice(end + 1);
      if (!line.trim()) continue;
      const result = accept(JSON.parse(line));
      if (result !== undefined) return result;
    }
    if (done) return undefined;
  }
}
