import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import type { ConfigResponse } from '../../../src/contracts/config';
import type { PoolCheckItemResponse, PoolCheckProgressEvent, PoolCheckResponse } from '../../../src/contracts/pool-check';
import { countPoolTextLines } from '../../../src/domain/pool-text';
import type { ApiClient } from '../api/client';
import { errorMessage, isAbort } from '../api/errors';
import type { ConsoleTone, PoolCheckProgressState } from '../components/dashboard-page';
import type { RequestState } from './request-state';
import { describeBatch, remainingBatch } from './batch-resume';
import { formatProbeLog, shouldLogProbe } from '../components/probe-log';

/** 批量检测中断时的进度摘要。 */
interface BatchInterrupt {
  readonly checked: number;
  readonly total: number;
  readonly valid: number;
  readonly rate: string;
  readonly unchecked: number;
}

interface BatchCheckOptions {
  readonly client: ApiClient;
  readonly config: RequestState<ConfigResponse>;
  readonly webCheckConcurrency: number;
  readonly notify: (message: string, type?: 'success' | 'error') => void;
  readonly appendConsoleLog: (message: string, tone?: ConsoleTone) => void;
  readonly onInterrupt: () => void;
}

/** 批量检测的完整生命周期；所有输入替换都取消旧请求并使旧结果失效。 */
export function useBatchCheck({ client, config, webCheckConcurrency, notify, appendConsoleLog, onInterrupt }: BatchCheckOptions) {
  const [ipText, setIpText] = useState('');
  const [batch, setBatch] = useState<RequestState<PoolCheckResponse>>({ status: 'idle' });
  const [checkingBatch, setCheckingBatch] = useState(false);
  const [batchProgressState, setBatchProgressState] = useState<PoolCheckProgressState | null>(null);
  const [batchReport, setBatchReport] = useState<ReturnType<typeof describeBatch> | null>(null);
  const [batchInterrupt, setBatchInterrupt] = useState<BatchInterrupt | null>(null);
  const activeBatch = useRef<AbortController | null>(null);
  const aliveSoFar = useRef(0);
  const batchSource = useRef('');
  const batchCompleted = useRef(new Set<number>());
  const batchGroups = useRef(new Map<number, PoolCheckItemResponse[]>());
  const batchSourceMap = useRef<readonly number[] | null>(null);

  useEffect(() => () => { activeBatch.current?.abort(); }, []);

  /** 所有输入替换都走这里：旧检测必须中止，旧结果也必须立即失效。 */
  const replaceIpText = useCallback((value: string): void => {
    activeBatch.current?.abort();
    activeBatch.current = null;
    setCheckingBatch(false);
    setIpText(value);
    setBatch({ status: 'idle' });
    setBatchReport(null);
    setBatchProgressState(null);
    setBatchInterrupt(null);
    batchSource.current = '';
    batchCompleted.current.clear();
    batchGroups.current.clear();
    batchSourceMap.current = null;
  }, []);

  const handleCheckBatch = (resume = false): void => {
    if (config.status !== 'ready') {
      notify(config.status === 'error' ? config.message : '正在读取配置，请稍后检测', 'error');
      return;
    }
    if (activeBatch.current) return;
    const sourceText = resume ? batchSource.current : ipText;
    const resumed = resume ? remainingBatch(sourceText, batchCompleted.current) : null;
    const text = resumed?.text ?? sourceText;
    if (!text.trim()) {
      notify(resume ? '没有未完成的检测项' : '请先输入或从库加载 IP', 'error');
      return;
    }
    if (!resume) {
      batchSource.current = sourceText;
      batchCompleted.current.clear();
      batchGroups.current.clear();
      batchSourceMap.current = null;
      aliveSoFar.current = 0;
      setBatchReport(describeBatch(sourceText, batchGroups.current, batchCompleted.current));
    }
    if (resumed) {
      // An unfinished source is retried as a whole; its partial group must be replaced.
      for (const index of batchGroups.current.keys()) {
        if (!batchCompleted.current.has(index)) batchGroups.current.delete(index);
      }
      aliveSoFar.current = [...batchGroups.current.values()].flat().filter(item => item.status === 'alive').length;
      batchSourceMap.current = resumed.sourceIndices;
      setBatchReport(describeBatch(sourceText, batchGroups.current, batchCompleted.current));
    }
    const retained = [...batchGroups.current.values()].flat().length;
    const controller = new AbortController();
    activeBatch.current = controller;
    setCheckingBatch(true);
    setBatch({ status: 'loading' });
    const total = countPoolTextLines(text);
    setBatchProgressState({ completed: retained, total: retained + total });
    appendConsoleLog(`[批量] ${resume ? '继续检测未完成项' : '开始检测清洗'} · ${total} 个地址`);
    client.checkBatch(text, controller.signal, (event: PoolCheckProgressEvent) => {
      if (activeBatch.current !== controller) return;
      setBatchProgressState({ completed: retained + event.completed, total: retained + event.total });
      if (event.item.status === 'alive') aliveSoFar.current += 1;
      const sourceIndex = batchSourceMap.current?.[event.sourceIndex] ?? event.sourceIndex;
      const group = batchGroups.current.get(sourceIndex) ?? [];
      group.push(event.item);
      batchGroups.current.set(sourceIndex, group);
      if (event.sourceComplete) batchCompleted.current.add(sourceIndex);
      const statusLabel = formatProbeLog(event.item);
      const tone: ConsoleTone = event.item.status === 'alive' ? 'success' : event.item.status === 'dead' ? 'error' : 'warning';
      if (shouldLogProbe(event.item)) appendConsoleLog(`[批量] ${event.item.address} · ${statusLabel}`, tone);
    }, webCheckConcurrency)
      .then((report) => {
        if (activeBatch.current !== controller) return;
        activeBatch.current = null;
        setCheckingBatch(false);
        const items = [...batchGroups.current.values()].flat();
        const combined: PoolCheckResponse = {
          ...report,
          total: items.length,
          alive: items.filter(item => item.status === 'alive').length,
          dead: items.filter(item => item.status === 'dead').length,
          unknown: items.filter(item => item.status === 'unknown').length,
          items,
        };
        setBatchProgressState({ completed: items.length, total: items.length });
        setBatch({ status: 'ready', data: combined });
        setBatchReport(describeBatch(batchSource.current, batchGroups.current, batchCompleted.current));
        batchSource.current = '';
        batchCompleted.current.clear();
        batchGroups.current.clear();
        batchSourceMap.current = null;
        appendConsoleLog(
          `[批量] 完成 · 可用 ${combined.alive} / 失效 ${combined.dead} / 未知 ${combined.unknown}${report.invalid.length ? ` / 无效 ${report.invalid.length}` : ''}`,
          combined.unknown ? 'warning' : combined.alive ? 'success' : 'error',
        );
        notify(
          `检测完成：可用 ${combined.alive}，失效 ${combined.dead}，未知 ${combined.unknown}${report.invalid.length ? `，无效 ${report.invalid.length}` : ''}`,
          combined.alive > 0 ? 'success' : 'error',
        );
      })
      .catch((error: unknown) => {
        if (isAbort(error) || activeBatch.current !== controller) return;
        activeBatch.current = null;
        setCheckingBatch(false);
        setBatchReport(describeBatch(batchSource.current, batchGroups.current, batchCompleted.current));
        batchSource.current = '';
        batchCompleted.current.clear();
        batchGroups.current.clear();
        batchSourceMap.current = null;
        const message = errorMessage(error);
        setBatch({ status: 'error', message });
        appendConsoleLog(`[批量] ${message}`, 'error');
        notify(message, 'error');
      });
  };

  const handleStopBatch = (): void => {
    const controller = activeBatch.current;
    if (!controller) return;
    onInterrupt();
    controller.abort();
    activeBatch.current = null;
    setCheckingBatch(false);
    setBatchReport(describeBatch(batchSource.current, batchGroups.current, batchCompleted.current));
    const total = countPoolTextLines(batchSource.current);
    const completed = batchCompleted.current.size;
    setBatchInterrupt({
      checked: completed,
      total,
      valid: aliveSoFar.current,
      rate: total ? (aliveSoFar.current / total * 100).toFixed(1) : '0.0',
      unchecked: Math.max(0, total - completed),
    });
  };

  const handleResumeBatch = (): void => {
    setBatchInterrupt(null);
    handleCheckBatch(true);
  };

  const handleAbandonBatch = (): void => {
    setBatchInterrupt(null);
    setBatch({ status: 'idle' });
    setBatchProgressState(null);
    aliveSoFar.current = 0;
    batchSource.current = '';
    batchCompleted.current.clear();
    batchGroups.current.clear();
    batchSourceMap.current = null;
    appendConsoleLog('[批量] 已放弃，保留已完成检测结果', 'warning');
  };

  return { ipText, batch, batchReport, checkingBatch, batchProgressState, batchInterrupt, replaceIpText,
    handleCheckBatch, handleStopBatch, handleResumeBatch, handleAbandonBatch };
}
