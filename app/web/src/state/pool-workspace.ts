import type { ApiClient } from '../api/client';
import type { PoolPreviewResponse, PoolSaveMode } from '../../../src/contracts/pool';
import { TRASH_POOL_KEY } from '../../../src/contracts/pool';
import { readPoolSnapshot } from '../../../src/domain/pool-snapshot';
import { errorMessage } from '../api/errors';

export function invalidPoolLines(content: string): readonly string[] {
  return readPoolSnapshot(content).invalid.filter(line => !line.startsWith('#'));
}

/** 保留写入回执，避免 KV 的旧读取覆盖已保存内容。 */
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
  private readonly reads = new Map<string, string>();
  constructor(private readonly client: ApiClient, private readonly changed = () => {}) {}
  forgetPool(key: string): void {
    this.confirmed.delete(key);
    this.reads.delete(key);
    if (key === this.key) {
      this.cancelRead(); this.invalidate();
      this.content = undefined; this.divergent = undefined; this.message = '';
    }
    this.changed();
  }
  select(key: string): void {
    if (key === this.key) return;
    this.cancelRead();
    this.invalidate();
    this.key = key;
    this.content = this.confirmed.get(key)?.content ?? this.reads.get(key);
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
  async read(): Promise<string | undefined> {
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
      if (result.key !== key) throw new Error('返回的 IP 池与请求不符');
      const confirmed = this.confirmed.get(key);
      this.reads.set(key, result.content);
      this.divergent = confirmed && confirmed.content !== result.content ? result.content : undefined;
      if (!confirmed) this.content = result.content;
      return this.content;
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
    return this.write(plan.poolKey, plan.content, plan.mode);
  }
  async append(content: string): Promise<boolean> {
    if (this.writing) return false;
    this.invalidate();
    if (this.key === TRASH_POOL_KEY || invalidPoolLines(content).length || !readPoolSnapshot(content).entries.size) {
      this.message = '没有可入库的有效地址，请检查输入'; this.changed(); return false;
    }
    return this.write(this.key, content, 'append');
  }
  private async write(poolKey: string, content: string, mode: PoolSaveMode): Promise<boolean> {
    const plan = this.preview;
    this.writing = true;
    this.cancelRead();
    this.message = '';
    this.changed();
    try {
      // 写入开始后等待结果，防止重复提交。
      const result = await this.client.savePool(poolKey, content, mode, undefined, true);
      if (result.mode !== mode || (result.receipt && result.receipt.poolKey !== poolKey)) throw new Error('回执与提交对象不符');
      const receipt = result.receipt;
      if (receipt?.written) {
        this.confirmed.set(poolKey, { content: receipt.content, count: result.count });
        if (this.key === poolKey) { this.content = receipt.content; this.divergent = undefined; }
        this.message = '已保存 · ' + result.count + ' 条地址';
      } else if (receipt) {
        if (!this.confirmed.has(poolKey)) {
          this.reads.set(poolKey, receipt.content);
          if (this.key === poolKey) this.content = receipt.content;
        }
        this.message = '内容没有变化，未执行新写入';
      } else this.message = '请求成功，但未提供回执；请刷新列表核对';
      if (this.preview === plan) this.preview = undefined;
      return true;
    } catch (error) {
      this.message = '未取得成功确认：' + errorMessage(error) + '。服务端可能已执行，请核对后重试。';
      return false;
    } finally { this.writing = false; this.changed(); }
  }
  adoptRead(): void {
    if (this.divergent === undefined || this.writing) return;
    this.invalidate();
    this.content = this.divergent;
    this.reads.set(this.key, this.content);
    this.divergent = undefined;
    this.confirmed.delete(this.key);
    this.changed();
  }
  dispose(): void { this.cancelRead(); this.invalidate(); }
}
