import type { CleanPoolEvent, CleanPoolResponse } from '../../../src/contracts/pool';
import { ApiError } from './client';
import { isRecord } from '../../../src/contracts/parse';

export async function readCleanPoolStream(response: Response, onProgress?: (event: Extract<CleanPoolEvent, { type: 'progress' }>) => void): Promise<CleanPoolResponse> {
  if (!response.body || !response.headers.get('content-type')?.includes('application/x-ndjson')) throw new ApiError('洗库响应格式无效，请刷新后重试', response.status);
  const reader = response.body.getReader(), decoder = new TextDecoder();
  let pending = '', result: CleanPoolResponse | undefined;
  const consume = (line: string) => {
    if (!line.trim()) return;
    let event: CleanPoolEvent;
    try { event = JSON.parse(line); } catch { throw new ApiError('洗库响应损坏，未取得完成确认', 0); }
    if (!event || result) throw new ApiError('洗库响应顺序无效', 0);
    if (event.type === 'error' && typeof event.error === 'string') throw new ApiError(event.error, 0);
    if (event.type === 'progress' && Number.isSafeInteger(event.completed) && event.completed > 0 && event.total >= event.completed && typeof event.address === 'string' && isRecord(event.result) && ['alive', 'dead', 'unknown'].includes(String(event.result.status))) onProgress?.(event);
    else if (event.type === 'complete' && isCleanResult(event.result)) result = event.result;
    else if (event.type !== 'start') throw new ApiError('洗库响应格式无效', 0);
  };
  try {
    while (true) {
      const chunk = await reader.read();
      pending += decoder.decode(chunk.value, { stream: !chunk.done });
      let end: number;
      while ((end = pending.indexOf('\n')) >= 0) { consume(pending.slice(0, end)); pending = pending.slice(end + 1); }
      if (chunk.done) break;
    }
    consume(pending);
    if (!result) throw new ApiError('洗库连接已中断，未取得完成确认，请核对库存', 0);
    return result;
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

function isCleanResult(value: unknown): value is CleanPoolResponse {
  return isRecord(value) && value.ok === true && typeof value.poolKey === 'string' && typeof value.skipped === 'boolean'
    && ['checked', 'kept', 'trashed', 'unknown'].every(key => Number.isSafeInteger(value[key]) && (value[key] as number) >= 0)
    && (value.remaining === undefined || Number.isSafeInteger(value.remaining) && (value.remaining as number) >= 0);
}
