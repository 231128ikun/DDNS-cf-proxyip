import type { ApiClient } from '../api/client';
import { TRASH_POOL_KEY } from '../../../src/contracts/pool';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { errorMessage } from '../api/errors';

export function invalidPoolLines(content: string): readonly string[] {
  return readPoolSnapshot(content).invalid.filter(line => !line.startsWith('#'));
}

/** 写入后保留回执，不自动回读 KV。 */
export class PoolWorkspace {
  key = 'ip_pool_default';
  content: string | undefined;
  reading = false;
  writing = false;
  message = '';
  revision = 0;
  private readonly snapshots = new Map<string, string>();
  private readonly written = new Set<string>();
  private readController: AbortController | undefined;
  constructor(private readonly client: ApiClient, private readonly changed = () => {}) {}
  invalidate(): void { this.revision++; }
  select(key: string): void {
    if (key === this.key) return;
    this.dispose(); this.key = key;
    this.content = this.snapshots.get(key); this.message = ''; this.changed();
  }
  forgetPool(key: string): void {
    this.snapshots.delete(key);
    this.written.delete(key);
    if (this.key === key) { this.dispose(); this.content = undefined; this.message = ''; }
    this.changed();
  }
  async read(): Promise<string | undefined> {
    if (this.writing) return;
    this.readController?.abort();
    const controller = this.readController = new AbortController(), key = this.key;
    this.reading = true; this.message = ''; this.changed();
    try {
      const result = await this.client.readPool(key, controller.signal);
      if (controller.signal.aborted || key !== this.key) return;
      if (result.key !== key) throw new Error('返回的 IP 池不符');
      this.content = result.content; this.snapshots.set(key, result.content); this.written.delete(key);
      return result.content;
    } catch (error) {
      if (!controller.signal.aborted) this.message = errorMessage(error);
    } finally {
      if (this.readController === controller) { this.reading = false; this.changed(); }
    }
  }
  async save(content: string, mode: 'append' | 'remove'): Promise<boolean> {
    if (this.writing) return false;
    if (this.key === TRASH_POOL_KEY || invalidPoolLines(content).length || !readPoolSnapshot(content).entries.size) {
      this.message = '请先整理有效地址'; this.changed(); return false;
    }
    const key = this.key;
    this.dispose(); this.writing = true; this.message = ''; this.changed();
    try {
      const result = await this.client.savePool(key, content, mode, undefined, true);
      if (result.mode !== mode || result.receipt?.poolKey !== key) throw new Error('未取得有效写入回执');
      if (result.receipt.written || !this.written.has(key)) this.snapshots.set(key, result.receipt.content);
      if (result.receipt.written) this.written.add(key);
      if (this.key === key) this.content = this.snapshots.get(key);
      this.message = result.receipt.written
        ? `${mode === 'append' ? '已追加' : '已剔除'} ${mode === 'append' ? result.added : result.removed} 条 · 库内 ${result.count} 条`
        : '内容未变化，未写入';
      return true;
    } catch (error) {
      this.message = '未取得保存确认：' + errorMessage(error) + '。请核对后重试'; return false;
    } finally { this.writing = false; this.changed(); }
  }
  dispose(): void { this.invalidate(); this.readController?.abort(); this.readController = undefined; this.reading = false; }
}
