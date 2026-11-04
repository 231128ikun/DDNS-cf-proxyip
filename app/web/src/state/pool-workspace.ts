import type { ApiClient } from '../api/client';
import type { PoolPreviewResponse, PoolSaveMode } from '../../../src/contracts/pool';
import { TRASH_POOL_KEY } from '../../../src/contracts/pool';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { errorMessage } from '../api/errors';

export function invalidPoolLines(content: string): readonly string[] {
  return readPoolSnapshot(content).invalid.filter(line => !line.startsWith('#'));
}

/** One session's accepted writes are separate from eventually consistent reads. */
export class PoolWorkspace {
  key = 'ip_pool_default';
  content: string | undefined;
  divergent: string | undefined;
  confirmed = new Map<string, { content: string; count: number }>();
  preview: { poolKey: string; content: string; mode: PoolSaveMode; revision: number; data: PoolPreviewResponse } | undefined;
  revision = 0;
  reading = false;
  previewing = false;
  writing = false;
  message = '';
  private readGeneration = 0;
  private readController?: AbortController;
  private previewController: AbortController | undefined;
  constructor(private readonly client: ApiClient, private readonly changed = () => {}) {}
  select(key: string): void {
    if (key === this.key) return;
    this.cancelRead();
    this.invalidate();
    this.key = key;
    this.content = this.confirmed.get(key)?.content;
    this.divergent = undefined;
    this.message = '';
    this.changed();
  }
  invalidate(): void {
    this.revision++;
    this.previewController?.abort();
    this.previewController = undefined;
    this.previewing = false;
    if (this.preview) this.message = '操作对象已变化，请重新预览';
    this.preview = undefined;
    this.changed();
  }
  private cancelRead(): void {
    this.readGeneration++;
    this.readController?.abort();
    this.reading = false;
  }
  async read(): Promise<void> {
    if (this.writing) return;
    this.cancelRead();
    this.invalidate();
    const generation = this.readGeneration;
    const key = this.key;
    const controller = this.readController = new AbortController();
    this.reading = true;
    this.message = '';
    this.changed();
    try {
      const result = await this.client.readPool(key, controller.signal);
      if (generation !== this.readGeneration || key !== this.key || controller.signal.aborted) return;
      if (result.key !== key) throw new Error('读取快照的池与请求不符');
      const confirmed = this.confirmed.get(key);
      this.divergent = confirmed && confirmed.content !== result.content ? result.content : undefined;
      if (!confirmed) this.content = result.content;
    } catch (error) {
      if (generation === this.readGeneration && !controller.signal.aborted) this.message = errorMessage(error);
    } finally {
      if (generation === this.readGeneration) { this.reading = false; this.changed(); }
    }
  }
  async prepare(content: string, mode: PoolSaveMode): Promise<void> {
    if (this.writing) return;
    this.invalidate();
    this.message = '';
    if (this.key === TRASH_POOL_KEY) this.message = '垃圾桶仅支持恢复和清空';
    else if (invalidPoolLines(content).length) this.message = '存在无法识别的内容，请修正后重新预览';
    else if (mode !== 'replace' && !readPoolSnapshot(content).entries.size) this.message = '没有可操作的地址';
    if (this.message) { this.changed(); return; }
    const poolKey = this.key, revision = this.revision;
    const controller = this.previewController = new AbortController();
    this.previewing = true;
    this.changed();
    try {
      const data = await this.client.previewPool(poolKey, content, mode, controller.signal);
      if (revision !== this.revision || controller.signal.aborted || poolKey !== this.key) return;
      if (data.poolKey !== poolKey || data.mode !== mode) throw new Error('预览与操作对象不符，请重试');
      this.preview = { poolKey, content, mode, revision, data };
    } catch (error) {
      if (revision === this.revision && !controller.signal.aborted) this.message = errorMessage(error);
    } finally {
      if (revision === this.revision) { this.previewing = false; this.changed(); }
    }
  }
  async save(): Promise<boolean> {
    const plan = this.preview;
    if (this.writing || !plan || plan.revision !== this.revision || plan.poolKey !== this.key || !plan.data.changed) return false;
    this.writing = true;
    this.cancelRead();
    this.message = '';
    this.changed();
    try {
      // A client abort cannot undo a PUT; keep waiting and forbid duplicate commands.
      const result = await this.client.savePool(plan.poolKey, plan.content, plan.mode, undefined, true);
      if (result.mode !== plan.mode || (result.receipt && result.receipt.poolKey !== plan.poolKey)) throw new Error('回执与提交对象不符');
      const receipt = result.receipt;
      if (receipt?.written) {
        this.confirmed.set(plan.poolKey, { content: receipt.content, count: result.count });
        if (this.key === plan.poolKey) { this.content = receipt.content; this.divergent = undefined; }
        this.message = '本次操作已确认 · ' + result.count + ' 条地址（不代表全球最新值）';
      } else if (receipt) {
        if (!this.confirmed.has(plan.poolKey) && this.key === plan.poolKey) this.content = receipt.content;
        this.message = '读取快照无变化，未执行新写入；保留已有确认值';
      } else this.message = '请求成功，但未提供回执；保留当前显示，可显式读取快照';
      if (this.preview === plan) this.preview = undefined;
      return true;
    } catch (error) {
      this.message = '未取得成功确认：' + errorMessage(error) + '。服务端可能已执行，可用同一预览重试。';
      return false;
    } finally { this.writing = false; this.changed(); }
  }
  adoptRead(): void {
    if (this.divergent === undefined || this.writing) return;
    this.invalidate();
    this.content = this.divergent;
    this.divergent = undefined;
    this.confirmed.delete(this.key);
    this.changed();
  }
  dispose(): void { this.cancelRead(); this.invalidate(); }
}
