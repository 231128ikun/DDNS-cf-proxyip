import type { CheckPoolText } from '../application/check-pool';
import type { CheckTarget, CheckTargetReport } from '../application/check-target';
import type { EffectiveConfigSource, ResolvedConfig } from '../application/config-service';
import type { CleanPool } from '../application/clean-pool';
import { DomainBindingsInputError, type DomainBindings } from '../application/domain-bindings';
import { PoolInputError, type PoolService } from '../application/pool-service';
import type { RemoteLoadFailure, RemotePoolLoader } from '../application/remote-pool-loader';
import {
  parseAppConfig,
  toPublicConfig,
  type AppConfig,
  type ConfigResponse,
} from '../contracts/config';
import type { MaintenanceRunResponse, SaveDomainBindingOrderRequest, SaveDomainBindingsRequest } from '../contracts/maintenance';
import type {
  CreatePoolRequest,
  CreatePoolResponse,
  PoolContentResponse,
  PoolSaveResponse,
  PoolsResponse,
  RenamePoolRequest,
  RestoreTrashRequest,
  RestoreTrashResponse,
  SavePoolOrderRequest,
  SavePoolRequest,
} from '../contracts/pool';
import {
  parseCheckProxyInput,
  type CheckTargetResponse,
  type HealthResponse,
  type ProbeResponse,
} from '../contracts/probe';
import type { RemoteLoadRequest, RemoteLoadResponse } from '../contracts/remote-load';
import type { TargetStatusResponse } from '../contracts/target-status';
import { TargetStatusInputError, type TargetStatus } from '../application/target-status';
import type { TargetRecords } from '../application/target-records';
import type { MaintenanceJobResult } from '../jobs/maintenance-job';
import { countPoolTextLines } from '../domain/pool-text';
import type { ProbeResult } from '../domain/probe-result';
import { errorResponse, jsonResponse, readJsonBody, Router } from './router';

export interface HttpAppDependencies {
  /** 探测入口：内部负责域名解析与逐地址探测。 */
  readonly checkTarget: CheckTarget;
  readonly version: string;
  readonly configSource?: EffectiveConfigSource;
  /** 未绑定 KV 时为空；此时 IP 池相关接口返回 503。 */
  readonly pools?: PoolService;
  /** 一键洗库用例；与维护流程共用同一个垃圾桶写入实现。 */
  readonly cleanPool?: CleanPool;
  readonly checkPool?: CheckPoolText;
  /** 配置读写入口；未绑定 KV 时为空，接口返回 503。 */
  readonly config?: ConfigGateway;
  /** 服务端远程加载器，前端不允许直接访问第三方地址。 */
  readonly remotePoolLoader?: RemotePoolLoader;
  /** 域名池绑定读写；未绑定 KV 时为空。 */
  readonly domainBindings?: DomainBindings;
  /** 手动维护入口；与 cron 共用同一 runner。 */
  readonly maintenance?: MaintenanceRunner;
  /** “解析实况”当前域名记录的只读来源；未绑定 KV 时为空。 */
  readonly targetStatus?: TargetStatus;
  /** 手动增删当前维护目标 DNS 记录的写入口；未绑定 KV 时为空。 */
  readonly targetRecords?: TargetRecords;
}

/** 维护 runner 的窄接口：HTTP 层只负责触发，不接触 KV / Cloudflare 凭据。 */
export interface MaintenanceRunner {
  run(isManual: boolean): Promise<MaintenanceJobResult>;
}

/** 结构化的配置读写契约，`ConfigService` 天然满足，测试里可以直接给桩对象。 */
export interface ConfigGateway {
  resolve(): Promise<ResolvedConfig>;
  save(config: AppConfig): Promise<void>;
}

export interface HttpApp {
  fetch(request: Request, env?: unknown, context?: unknown): Promise<Response>;
  /** 便于测试与内部调用：接受相对路径或完整 Request。 */
  request(input: string | Request, init?: RequestInit): Promise<Response>;
}

export function createHttpApp(dependencies: HttpAppDependencies): HttpApp {
  const router = new Router();

  router.get('/api/health', () => {
    const response: HealthResponse = {
      ok: true,
      version: dependencies.version,
      ...(dependencies.configSource ? { configSource: dependencies.configSource } : {}),
    };
    return jsonResponse(response);
  });

  /**
   * 面板探测入口：`txt@域名` 取 TXT 列表，裸域名解析 A/AAAA，
   * IP 与带端口目标直接探测；解析失败按输入错误返回，不会把节点判成失效。
   */
  router.post('/api/check', async (context) => {
    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    const parsed = parseCheckProxyInput((body.value as { proxyip?: unknown } | null)?.proxyip);
    if (!parsed.ok) return errorResponse('invalid proxyip', 400);

    const outcome = await dependencies.checkTarget.execute(parsed.value, { signal: context.request.signal });
    if (!outcome.ok) return errorResponse(outcome.message, 400);

    return jsonResponse(toCheckTargetResponse(outcome.report));
  });

  router.get('/api/pools', async () => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const response: PoolsResponse = { pools: await pools.list() };
    return jsonResponse(response);
  });

  router.post('/api/pools', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      const pool = await pools.create((body.value as CreatePoolRequest | null)?.displayName);
      const response: CreatePoolResponse = { ok: true, key: pool.key, displayName: pool.name };
      return jsonResponse(response);
    });
  });

  // 固定路径必须先于 /pools/:key 注册，避免 'order' 被当成池 key。
  router.put('/api/pools/order', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      await pools.saveOrder((body.value as SavePoolOrderRequest | null)?.order);
      return jsonResponse({ ok: true });
    });
  });

  router.post('/api/pools/trash/clear', async () => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    await pools.clearTrash();
    return jsonResponse({ ok: true });
  });

  router.post('/api/pools/trash/restore', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      const input = body.value as RestoreTrashRequest | null;
      const result = await pools.restoreTrash(input?.addresses, input?.restoreToSource, input?.targetPool);
      const response: RestoreTrashResponse = result;
      return jsonResponse(response);
    });
  });

  /**
   * 一键洗库：读池、批量检测、有效项写回、失效项入桶，全部在服务端一次完成。
   * 面板不再自己拼这几步——main 上「垃圾桶被绕过统一入口直接追加」的 bug 就出在那里。
   */
  router.post('/api/pools/:key/clean', async (context) => {
    const cleanPool = dependencies.cleanPool;
    if (!cleanPool) return errorResponse('pool storage unavailable', 503);

    return await mapApplicationInputError(async () => {
      const response = await cleanPool.execute(context.params.key!, { signal: context.request.signal });
      return jsonResponse(response);
    });
  });

  router.get('/api/pools/:key', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    return await mapApplicationInputError(async () => {
      const response: PoolContentResponse = {
        key: context.params.key!,
        content: await pools.read(context.params.key),
      };
      return jsonResponse(response);
    });
  });

  router.put('/api/pools/:key', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      const input = body.value as SavePoolRequest | null;
      const result = await pools.save(context.params.key, input?.content, input?.mode);
      const response: PoolSaveResponse = result;
      return jsonResponse(response);
    });
  });

  router.add('PATCH', '/api/pools/:key', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      await pools.rename(context.params.key, (body.value as RenamePoolRequest | null)?.displayName);
      return jsonResponse({ ok: true });
    });
  });

  router.delete('/api/pools/:key', async (context) => {
    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    return await mapApplicationInputError(async () => {
      await pools.remove(context.params.key);
      return jsonResponse({ ok: true });
    });
  });

  router.get('/api/domain-bindings', async () => {
    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse('binding storage unavailable', 503);

    return jsonResponse(await bindings.list());
  });

  router.put('/api/domain-bindings', async (context) => {
    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse('binding storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      await bindings.save((body.value as SaveDomainBindingsRequest | null)?.mapping);
      return jsonResponse({ ok: true });
    });
  });

  router.put('/api/domain-bindings/order', async (context) => {
    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse('binding storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      await bindings.saveOrder((body.value as SaveDomainBindingOrderRequest | null)?.order);
      return jsonResponse({ ok: true });
    });
  });

  router.post('/api/maintenance/run', async () => {
    const maintenance = dependencies.maintenance;
    if (!maintenance) return errorResponse('maintenance unavailable', 503);

    const { run } = await maintenance.run(true);
    return jsonResponse(toMaintenanceResponse(run));
  });

  /**
   * “解析实况”当前域名记录：只读查询 Cloudflare DNS，
   * 手动新增/删除记录仍由维护流程统一执行，面板不提供旁路写入口。
   */
  router.get('/api/current-status', async (context) => {
    const targetStatus = dependencies.targetStatus;
    if (!targetStatus) return errorResponse('target status unavailable', 503);

    return await mapApplicationInputError(async () => {
      const response: TargetStatusResponse = await targetStatus.execute(context.url.searchParams.get('target') ?? '');
      return jsonResponse(response);
    });
  });

  /** 手动添加一条记录到选中的维护目标；与定时维护共用同一个 DNS 写入实现。 */
  router.post('/api/add-record', async (context) => {
    const targetRecords = dependencies.targetRecords;
    if (!targetRecords) return errorResponse('target records unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      const input = body.value as { target?: unknown; value?: unknown } | null;
      const response = await targetRecords.add(
        typeof input?.target === 'string' ? input.target : '',
        typeof input?.value === 'string' ? input.value : '',
      );
      return jsonResponse(response);
    });
  });

  /** 手动删除当前维护目标的一条记录；TXT 模式只删单条地址。 */
  router.post('/api/delete-record', async (context) => {
    const targetRecords = dependencies.targetRecords;
    if (!targetRecords) return errorResponse('target records unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      const input = body.value as { target?: unknown; recordId?: unknown; address?: unknown } | null;
      const response = await targetRecords.remove(
        typeof input?.target === 'string' ? input.target : '',
        typeof input?.recordId === 'string' ? input.recordId : '',
        typeof input?.address === 'string' ? input.address : undefined,
      );
      return jsonResponse(response);
    });
  });

  router.get('/api/config', async () => {
    const config = dependencies.config;
    if (!config) return errorResponse('config storage unavailable', 503);

    return jsonResponse(toConfigResponse(await config.resolve()));
  });

  router.put('/api/config', async (context) => {
    const config = dependencies.config;
    if (!config) return errorResponse('config storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    // 未提交的密钥字段沿用已存值，空字符串才代表清空，避免前端回写时抹掉密钥。
    const resolved = await config.resolve();
    const parsed = parseAppConfig(body.value, resolved.config);
    if (!parsed.ok) return errorResponse(parsed.message, 400);

    await config.save(parsed.value);
    return jsonResponse(toConfigResponse({ config: parsed.value, source: 'kv' }));
  });

  router.post('/api/remote-load', async (context) => {
    const loader = dependencies.remotePoolLoader;
    if (!loader) return errorResponse('remote load unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    const url = (body.value as RemoteLoadRequest | null)?.url;
    const result = await loader.load(typeof url === 'string' ? url : '', { signal: context.request.signal });
    if (!result.ok) return errorResponse(result.reason, remoteLoadStatus(result.reason));

    const response: RemoteLoadResponse = {
      url: result.finalUrl,
      content: result.content,
      count: countPoolTextLines(result.content),
    };
    return jsonResponse(response);
  });

  const fetch = async (request: Request): Promise<Response> => {
    try {
      const matched = await router.handle(request);
      if (matched) return matched;

      return errorResponse('not found', 404);
    } catch (error) {
      console.error('Unhandled worker error', error);
      return errorResponse('internal error', 500);
    }
  };

  return {
    fetch,
    request: (input, init) =>
      fetch(typeof input === 'string' ? new Request(new URL(input, 'http://localhost'), init) : input),
  };
}

/** 把用例层的输入错误映射成 400，其余异常继续向上抛给统一错误处理。 */
async function mapApplicationInputError(run: () => Promise<Response>): Promise<Response> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PoolInputError || error instanceof DomainBindingsInputError || error instanceof TargetStatusInputError) {
      return errorResponse(error.message, 400);
    }
    throw error;
  }
}

function toConfigResponse(resolved: ResolvedConfig): ConfigResponse {
  return {
    source: resolved.source,
    ...(resolved.notice ? { notice: resolved.notice } : {}),
    config: toPublicConfig(resolved.config),
  };
}

/** 远程加载失败按语义映射状态码，前端不必解析错误文案。 */
function remoteLoadStatus(reason: RemoteLoadFailure): number {
  if (reason === 'invalid-url' || reason === 'blocked-host') return 400;
  if (reason === 'too-large') return 413;
  if (reason === 'timeout') return 504;
  return 502;
}

/** 维护结果只暴露面板需要的信息，绝不回传 Cloudflare 凭据。 */
function toMaintenanceResponse(run: MaintenanceJobResult['run']): MaintenanceRunResponse {
  return {
    ok: true,
    changed: run.changed,
    insufficient: run.insufficient,
    errors: run.errors,
    probeErrors: run.probeErrors,
    results: run.results.map(({ target, poolKey, poolName, report, error }) => ({
      domain: target.domain,
      mode: target.mode,
      poolKey,
      poolName,
      dnsUpdated: report?.dnsUpdated ?? false,
      added: report?.added ?? 0,
      deleted: report?.deleted ?? 0,
      probeErrors: report?.probeErrors ?? 0,
      error: error ?? (report?.errors.length ? report.errors.join('；') : null),
    })),
  };
}

function toCheckTargetResponse(report: CheckTargetReport): CheckTargetResponse {
  const { source } = report;
  return {
    ok: true,
    input: report.input,
    source: source.kind === 'direct'
      ? { kind: 'direct' }
      : { kind: source.kind, host: source.host, addresses: source.addresses },
    items: report.items.map((item) => ({ address: item.address, result: toProbeResponse(item.result) })),
    skipped: report.skipped,
  };
}

function toProbeResponse(result: ProbeResult): ProbeResponse {
  const { target: _target, ...response } = result;
  return response;
}
