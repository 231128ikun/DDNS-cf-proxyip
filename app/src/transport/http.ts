import type { CheckPoolText, PoolCheckItem, PoolCheckReport } from '../application/check-pool';
import { CheckProxy } from '../application/check-proxy';
import type { EffectiveConfigSource, ResolvedConfig } from '../application/config-service';
import { DomainBindingsInputError, type DomainBindings } from '../application/domain-bindings';
import { PoolInputError, type PoolService } from '../application/pool-service';
import type { RemoteLoadFailure, RemotePoolLoader } from '../application/remote-pool-loader';
import { createProbeAdapterFromConfig } from '../config/runtime';
import {
  createDefaultConfig,
  parseAppConfig,
  toPublicConfig,
  toProbeConfig,
  type AppConfig,
  type ConfigResponse,
  type ProbeTestRequest,
} from '../contracts/config';
import type { CheckPoolRequest, PoolCheckItemResponse, PoolCheckResponse } from '../contracts/pool-check';
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
import type { HealthResponse, ProbeResponse } from '../contracts/probe';
import { parseCheckProxyInput } from '../contracts/probe';
import type { RemoteLoadRequest, RemoteLoadResponse } from '../contracts/remote-load';
import type { MaintenanceJobResult } from '../jobs/maintenance-job';
import { formatPoolEntry } from '../domain/pool-entry';
import { countPoolTextLines } from '../domain/pool-text';
import type { ProbeResult } from '../domain/probe-result';
import { isAuthorized } from './auth';
import { errorResponse, jsonResponse, readJsonBody, Router, type RouteContext } from './router';

export interface HttpAppDependencies {
  readonly checkProxy: CheckProxy;
  readonly version: string;
  readonly configSource?: EffectiveConfigSource;
  readonly authKey?: string;
  readonly assets?: Fetcher;
  /** 未绑定 KV 时为空；此时 IP 池相关接口返回 503。 */
  readonly pools?: PoolService;
  readonly checkPool?: CheckPoolText;
  /** 配置读写入口；未绑定 KV 时为空，接口返回 503。 */
  readonly config?: ConfigGateway;
  /** 服务端远程加载器，前端不允许直接访问第三方地址。 */
  readonly remotePoolLoader?: RemotePoolLoader;
  /** 域名池绑定读写；未绑定 KV 时为空。 */
  readonly domainBindings?: DomainBindings;
  /** 手动维护入口；与 cron 共用同一 runner。 */
  readonly maintenance?: MaintenanceRunner;
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

  /** 所有 /api/* 业务路由共用同一个鉴权入口，避免新增路由时漏掉校验。 */
  const guard = (context: RouteContext): Response | null =>
    isAuthorized(context.request, dependencies.authKey) ? null : errorResponse('unauthorized', 401);

  router.get('/', (context) => {
    if (dependencies.assets) return dependencies.assets.fetch(context.request);
    return jsonResponse({
      name: 'ddns-cf-proxyip',
      version: dependencies.version,
      api: '/api/check?proxyip=1.2.3.4:443',
    });
  });

  router.get('/api/health', () => {
    const response: HealthResponse = {
      ok: true,
      version: dependencies.version,
      ...(dependencies.configSource ? { configSource: dependencies.configSource } : {}),
    };
    return jsonResponse(response);
  });

  router.get('/api/check', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const parsed = parseCheckProxyInput(context.url.searchParams.get('proxyip'));
    if (!parsed.ok) return errorResponse('invalid proxyip', 400);

    const result = await dependencies.checkProxy.execute(parsed.value, { signal: context.request.signal });
    return jsonResponse(toProbeResponse(result));
  });

  router.post('/api/check', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    const parsed = parseCheckProxyInput((body.value as { proxyip?: unknown } | null)?.proxyip);
    if (!parsed.ok) return errorResponse('invalid proxyip', 400);

    const result = await dependencies.checkProxy.execute(parsed.value, { signal: context.request.signal });
    return jsonResponse(toProbeResponse(result));
  });

  router.post('/api/check/batch', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const checkPool = dependencies.checkPool;
    if (!checkPool) return errorResponse('probe unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    const text = (body.value as CheckPoolRequest | null)?.text;
    if (typeof text !== 'string' || !text.trim()) return errorResponse('invalid text', 400);

    const report = await checkPool.execute(text, { signal: context.request.signal });
    return jsonResponse(toPoolCheckResponse(report));
  });

  router.get('/api/pools', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const response: PoolsResponse = { pools: await pools.list() };
    return jsonResponse(response);
  });

  router.post('/api/pools', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

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
    const denied = guard(context);
    if (denied) return denied;

    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      await pools.saveOrder((body.value as SavePoolOrderRequest | null)?.order);
      return jsonResponse({ ok: true });
    });
  });

  router.post('/api/pools/trash/clear', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    await pools.clearTrash();
    return jsonResponse({ ok: true });
  });

  router.post('/api/pools/trash/restore', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

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

  router.get('/api/pools/:key', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

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
    const denied = guard(context);
    if (denied) return denied;

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
    const denied = guard(context);
    if (denied) return denied;

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
    const denied = guard(context);
    if (denied) return denied;

    const pools = dependencies.pools;
    if (!pools) return errorResponse('pool storage unavailable', 503);

    return await mapApplicationInputError(async () => {
      await pools.remove(context.params.key);
      return jsonResponse({ ok: true });
    });
  });

  router.get('/api/domain-bindings', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse('binding storage unavailable', 503);

    return jsonResponse(await bindings.list());
  });

  router.put('/api/domain-bindings', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

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
    const denied = guard(context);
    if (denied) return denied;

    const bindings = dependencies.domainBindings;
    if (!bindings) return errorResponse('binding storage unavailable', 503);

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    return await mapApplicationInputError(async () => {
      await bindings.saveOrder((body.value as SaveDomainBindingOrderRequest | null)?.order);
      return jsonResponse({ ok: true });
    });
  });

  router.post('/api/maintenance/run', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const maintenance = dependencies.maintenance;
    if (!maintenance) return errorResponse('maintenance unavailable', 503);

    const { run } = await maintenance.run(true);
    return jsonResponse(toMaintenanceResponse(run));
  });

  router.get('/api/config', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const config = dependencies.config;
    if (!config) return errorResponse('config storage unavailable', 503);

    return jsonResponse(toConfigResponse(await config.resolve()));
  });

  router.put('/api/config', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

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

  router.post('/api/config/probe/test', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

    const body = await readJsonBody(context.request);
    if (!body.ok) return errorResponse('invalid json', 400);

    const input = body.value as ProbeTestRequest | null;
    const parsed = parseCheckProxyInput(input?.proxyip);
    if (!parsed.ok) return errorResponse('invalid proxyip', 400);

    const template = input?.urlTemplate?.trim();
    const defaultConfig = createDefaultConfig();
    const checker = template
      ? new CheckProxy(
          createProbeAdapterFromConfig(toProbeConfig({
            ...defaultConfig,
            checkApi: template,
            checkApiBackup: '',
            probeMode: 'external-api',
          })),
        )
      : dependencies.checkProxy;

    const result = await checker.execute(parsed.value, { signal: context.request.signal });
    return jsonResponse(toProbeResponse(result));
  });

  router.post('/api/remote-load', async (context) => {
    const denied = guard(context);
    if (denied) return denied;

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

      const path = new URL(request.url).pathname;
      const canServeAsset = request.method === 'GET' || request.method === 'HEAD';
      if (dependencies.assets && canServeAsset && !path.startsWith('/api/')) {
        return await dependencies.assets.fetch(request);
      }
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
    if (error instanceof PoolInputError || error instanceof DomainBindingsInputError) {
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

function toProbeResponse(result: ProbeResult): ProbeResponse {
  const { target: _target, ...response } = result;
  return response;
}

function toPoolCheckResponse(report: PoolCheckReport): PoolCheckResponse {
  return {
    total: report.total,
    alive: report.alive,
    dead: report.dead,
    unknown: report.unknown,
    invalid: report.invalid,
    items: report.items.map(toPoolCheckItemResponse),
  };
}

function toPoolCheckItemResponse(item: PoolCheckItem): PoolCheckItemResponse {
  const { result, entry } = item;
  const primary = result.exits[0];
  const asn = primary?.asn ?? entry.asn ?? undefined;
  const country = primary?.country ?? entry.country ?? undefined;
  return {
    address: item.address,
    status: result.status,
    exitFamily: result.exitFamily,
    ...(result.exitIp ? { exitIp: result.exitIp } : {}),
    ...(result.latencyMs === undefined ? {} : { latencyMs: result.latencyMs }),
    ...(result.code ? { code: result.code } : {}),
    ...(result.message ? { message: result.message } : {}),
    ...(asn ? { asn } : {}),
    ...(country ? { country } : {}),
    // 复用领域层的序列化规则，保证入库文本与监控流程完全一致。
    line: formatPoolEntry(entry),
  };
}
