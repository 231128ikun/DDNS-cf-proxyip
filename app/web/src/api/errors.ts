import { ApiError } from './client';

/** 前端统一的请求错误文案，避免每个页面各写一份判断。 */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return '鉴权失败，请检查访问密钥';
    if (error.status === 503) return '该功能需要绑定 KV/配置后才可用';
    return error.message;
  }
  return error instanceof Error ? error.message : '请求失败';
}

export function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}