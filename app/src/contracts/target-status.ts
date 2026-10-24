import type { TargetMode } from '../domain/managed-target';

/** 单个 DNS 记录的只读视图；`content` 按 Cloudflare 原始值返回，由前端按记录类型解析。 */
export interface TargetStatusRecord {
  readonly id: string;
  readonly type: 'A' | 'AAAA' | 'TXT';
  readonly name: string;
  readonly content: string;
}

/** `GET /api/current-status` 的响应：只读展示，绝不回传 Cloudflare 凭据。 */
export interface TargetStatusResponse {
  readonly ok: true;
  readonly domain: string;
  readonly mode: TargetMode;
  readonly records: readonly TargetStatusRecord[];
}
