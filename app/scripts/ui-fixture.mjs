import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, resolve, sep } from 'node:path';
import { createContext, Script } from 'node:vm';
import { pathToFileURL } from 'node:url';

// main 的最后一套页面作为固定验收基准。只读取 Git 历史，不保存第二套源码。
export const UI_REFERENCE_REF = '81a41bd014c9d7ee2ec0cd50e9d43fff58c2b8f5';
const appRoot = resolve(import.meta.dirname, '..');
const webRoot = join(appRoot, 'dist', 'web');
const probeExits = [{ family: 'ipv4', ip: '198.51.100.42', asn: 'AS64500', country: 'US' }];
const mainProbe = { success: true, colo: 'SJC', time: 12, exits: probeExits.map((exit) => ({ ...exit, stack: exit.family })) };

export function createUiFixture() {
  const zones = [{ name: '测试权限', label: '测试权限', baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }];
  const targets = ['A', 'TXT'].map((mode) => ({ mode, domain: `${mode === 'A' ? 'edge' : 'proxy'}.example.com`,
    prefix: mode === 'A' ? 'edge' : 'proxy', baseDomain: 'example.com', zoneIndex: 0, port: mode === 'A' ? 443 : 'any',
    minActive: 3, exitFilter: 'any', country: '', asn: '', countries: [], asns: [], enabled: true }));
  const config = { zones, targets, apiKey: '', zoneId: '', checkApi: 'https://probe.example.test/?proxyip={proxyip}',
    checkApiBackup: '', dohApi: 'https://dns.example.test/dns-query', projectUrl: '', tgToken: '', tgId: '',
    tgEnabled: false, scheduledEnabled: true, settings: { CONCURRENT_CHECKS: 32, BACKEND_CONCURRENT_CHECKS: 4, CHECK_TIMEOUT: 15000,
      REMOTE_LOAD_TIMEOUT: 8000, DOH_TIMEOUT: 5000, DEFAULT_MIN_ACTIVE: 3, MAX_TRASH_SIZE: 1000 } };
  const pools = [{ key: 'ip_pool_default', name: '默认池', count: 2 }, { key: 'ip_pool_001', name: '香港节点', count: 2 },
    { key: 'ip_pool_002', name: '备用节点', count: 2 }, { key: 'ip_pool_trash', name: '垃圾桶', count: 0 }];
  const bindings = { items: targets.map((target, index) => ({ key: `${target.domain}|${target.mode}`, domain: target.domain,
    mode: target.mode, enabled: true, poolKey: pools[index ? 1 : 0].key, poolName: pools[index ? 1 : 0].name })) };
  const records = Object.fromEntries(targets.map((target) => [`${target.domain}|${target.mode}`, target.mode === 'A'
    ? [{ id: 'fixture-a', type: 'A', name: target.domain, content: '203.0.113.10' },
      { id: 'fixture-aaaa', type: 'AAAA', name: target.domain, content: '2001:db8::10' }]
    : [{ id: 'fixture-txt', type: 'TXT', name: target.domain, content: '"203.0.113.10:443,[2001:db8::10]:8443"' }]]));
  return { config, pools, bindings, records, nextRecord: 0, failConfigSave: false, failRecordSave: false,
    failOrderSave: null, orderSaveDelay: 0, orderChunkDelay: 0, poolListFailures: 0, bindingListFailures: 0,
    poolListDelay: 0, bindingListDelay: 0, configSaveDelay: 0, bindingSaveDelay: 0, bindingSaveFailures: 0,
    poolContents: {}, probeDelay: 0, probeMetrics: { active: 0, peak: 0 }, configDelay: 0, configFailures: 0 };
}

/** 等待服务器真正完成请求；按钮消失不能证明一次回读成功。 */
export async function waitForUiRequest(requests, start, path, method, status) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const request = requests.slice(start).find(item => item.path === path && item.method === method);
    if (request?.completed) {
      if (status !== undefined && request.status !== status) {
        throw new Error(`${method} ${path} 返回 ${request.status}，应为 ${status}`);
      }
      return request;
    }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`${method} ${path} 尚未完成`);
}

export function renderReference(config, ref = UI_REFERENCE_REF, login = false) {
  let source;
  try {
    source = execFileSync('git', ['show', `${ref}:_worker.js`], { cwd: appRoot, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    throw new Error(`无法读取 UI 基准 ${ref}；请获取该提交的 Git 历史后再运行验收`);
  }
  const context = createContext({ URL, Response, Request, Headers, AbortController,
    fetch: () => { throw new Error('UI reference cannot access network'); } });
  new Script(source.replace('export default {', 'const referenceWorker = {')).runInContext(context, { timeout: 1000 });
  return login ? context.renderLoginHTML(new URL('http://127.0.0.1/reference-login'))
    : context.renderHTML(config, { kvReady: true });
}

/** 本地验收：配置与绑定读写使用同次构建的 Worker 和内存 KV，外部操作使用替身。 */
export async function serveUiFixture({ reference = false, ref = UI_REFERENCE_REF, empty = false } = {}) {
  if (!existsSync(join(webRoot, 'index.html'))) throw new Error('请先运行 npm run build');
  const fixture = createUiFixture();
  if (empty) { fixture.config.zones = []; fixture.config.targets = []; fixture.bindings.items = []; }
  const referenceHtml = reference ? renderReference(fixture.config, ref) : null;
  const referenceLoginHtml = reference ? renderReference(fixture.config, ref, true) : null;
  const { default: worker } = await import(pathToFileURL(join(appRoot, 'dist', 'release', 'worker.js')).href);
  const kv = {
    async get(key, options) {
      if (/^ip_pool_(?:default|trash|\d{3})$/.test(key)) {
        const pool = fixture.pools.find(item => item.key === key);
        return fixture.poolContents[key] ?? (pool ? Array.from({ length: pool.count },
          (_, index) => `203.0.113.${index + 10}:443`).join('\n') : null);
      }
      const values = {
        app_config: fixture.config,
        domain_pool_mapping: Object.fromEntries(fixture.bindings.items.map(item => [item.key, item.poolKey])),
        domain_pool_order: fixture.bindings.items.map(item => item.key),
        ip_pool_names: Object.fromEntries(fixture.pools.map(item => [item.key, item.name])),
        ip_pool_order: fixture.pools.map(item => item.key),
      };
      if (!(key in values)) return null;
      const value = JSON.stringify(values[key]);
      return options === 'json' || options?.type === 'json' ? JSON.parse(value) : value;
    },
    async put(key, value) {
      if (/^ip_pool_(?:default|trash|\d{3})$/.test(key)) {
        fixture.poolContents[key] = value;
        if (!fixture.pools.some(item => item.key === key)) {
          fixture.pools.splice(fixture.pools.length - 1, 0, { key, name: key, count: 0 });
        }
        return;
      }
      const data = JSON.parse(value);
      if (key === 'app_config') fixture.config = data;
      else if (key === 'domain_pool_mapping') fixture.bindings.items = fixture.bindings.items.map(item => ({
        ...item, poolKey: data[item.key] ?? item.poolKey,
      }));
      else if (key === 'ip_pool_names') fixture.pools = fixture.pools.map(item => ({ ...item, name: data[item.key] ?? item.name }));
      else if (key === 'ip_pool_order') fixture.pools = data.map(key => fixture.pools.find(item => item.key === key)).filter(Boolean);
      else throw new Error(`Unexpected UI fixture KV write: ${key}`);
    },
    async list({ prefix = '' } = {}) {
      return { keys: fixture.pools.filter(item => item.key.startsWith(prefix)).map(item => ({ name: item.key })), list_complete: true };
    },
  };
  const requests = [];
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const json = (data, status = 200) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(data)); };
    if (url.pathname.startsWith('/api/')) {
      let body = '';
      for await (const chunk of request) body += chunk;
      const input = body ? JSON.parse(body) : {};
      const entry = { path: url.pathname, method: request.method, input, completed: false, status: null,
        startedAt: Date.now(), completedAt: null,
        query: Object.fromEntries(url.searchParams),
        surface: request.headers.referer?.includes('/reference') ? 'main' : 'current' };
      requests.push(entry);
      response.once('finish', () => { entry.status = response.statusCode; entry.completed = true; entry.completedAt = Date.now(); });
      response.once('close', () => {
        if (!entry.completed) { entry.completed = true; entry.aborted = true; entry.completedAt = Date.now(); }
      });
      if (url.pathname === '/api/auth/status') {
        const key = String(fixture.config.authKey ?? '').trim();
        const cookie = (request.headers.cookie ?? '').split(';').map(part => part.trim())
          .find(part => part.startsWith('ddns_auth='))?.slice('ddns_auth='.length) ?? '';
        const authenticated = !key || decodeURIComponent(cookie) === key;
        return json({ ok: true, enabled: Boolean(key), authenticated });
      }
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        const required = String(fixture.config.authKey ?? '').trim();
        if (required && String(input.key ?? '').trim() !== required) return json({ error: '未授权' }, 401);
        const headers = { 'content-type': 'application/json' };
        if (required) headers['set-cookie'] = `ddns_auth=${encodeURIComponent(required)}; Path=/; HttpOnly; SameSite=Lax`;
        response.writeHead(200, headers);
        return response.end(JSON.stringify({ ok: true, enabled: Boolean(required), authenticated: true }));
      }
      if (['/api/config', '/api/domain-bindings', '/api/pools'].includes(url.pathname)) {
        if (request.method === 'GET') {
          const [failureKey, delayKey] = url.pathname === '/api/config' ? ['configFailures', 'configDelay']
            : url.pathname === '/api/pools' ? ['poolListFailures', 'poolListDelay'] : ['bindingListFailures', 'bindingListDelay'];
          const failed = fixture[failureKey] > 0;
          if (failed) fixture[failureKey]--;
          if (fixture[delayKey]) await new Promise(resolve => setTimeout(resolve, fixture[delayKey]));
          if (failed) return json({ error: '模拟读取失败' }, 500);
        } else {
          const delay = url.pathname === '/api/config' ? fixture.configSaveDelay : fixture.bindingSaveDelay;
          if (delay) await new Promise(resolve => setTimeout(resolve, delay));
          if (url.pathname === '/api/config' && fixture.failConfigSave) {
            fixture.failConfigSave = false;
            return json({ error: '模拟配置保存失败' }, 500);
          }
          if (url.pathname === '/api/domain-bindings' && fixture.bindingSaveFailures > 0) {
            fixture.bindingSaveFailures--;
            return json({ error: '模拟绑定保存失败' }, 500);
          }
        }
        const result = await worker.fetch(new Request(url, { method: request.method,
          headers: { 'content-type': 'application/json', ...(request.headers.cookie ? { cookie: request.headers.cookie } : {}) },
          ...(body ? { body } : {}) }), { IP_DATA: kv });
        const data = await result.json();
        if (result.ok && url.pathname === '/api/domain-bindings' && request.method === 'GET') fixture.bindings = data;
        if (result.ok && url.pathname === '/api/pools' && request.method === 'GET') fixture.pools = data.pools;
        return json(data, result.status);
      }
      const { config, pools, bindings } = fixture;
      if (url.pathname === '/api/health') return json({ ok: true, version: 'fixture', configSource: 'kv' });
      if (url.pathname === '/api/save-config' && request.method === 'POST') {
        if (fixture.failConfigSave) {
          fixture.failConfigSave = false;
          return json({ success: false, error: '模拟配置保存失败' }, url.pathname === '/api/save-config' ? 200 : 500);
        }
        const update = input.config ?? input;
        Object.assign(config, update, { zones: update.zones.map((zone) => ({ ...zone,
          apiKey: zone.apiKey || config.zones.find((previous) => previous.baseDomain === zone.baseDomain)?.apiKey || '' })) });
        return json({ success: true, config });
      }
      const poolOrder = ['/api/pools/order', '/api/save-pool-order'].includes(url.pathname);
      const bindingOrder = ['/api/domain-bindings/order', '/api/save-domain-pool-order'].includes(url.pathname);
      if ((poolOrder || bindingOrder) && ['PUT', 'POST'].includes(request.method)) {
        if (fixture.orderSaveDelay) await new Promise(resolve => setTimeout(resolve, fixture.orderSaveDelay));
        const kind = poolOrder ? 'pools' : 'bindings';
        if (fixture.failOrderSave === kind) {
          fixture.failOrderSave = null;
          return json({ success: false, error: '模拟排序保存失败' }, url.pathname.includes('/save-') ? 200 : 500);
        }
        const items = poolOrder ? fixture.pools : fixture.bindings.items;
        const order = input.order;
        if (!Array.isArray(order) || order.length !== items.length || new Set(order).size !== items.length
          || order.some(key => !items.some(item => item.key === key))) {
          return json({ success: false, error: '排序必须完整保留原有条目' }, url.pathname.includes('/save-') ? 200 : 400);
        }
        const sorted = order.map(key => items.find(item => item.key === key));
        if (poolOrder) fixture.pools = sorted;
        else fixture.bindings.items = sorted;
        return json({ ok: true, success: true, pools: fixture.pools.map(item => item.key),
          poolNames: Object.fromEntries(fixture.pools.map(item => [item.key, item.name])),
          mapping: Object.fromEntries(fixture.bindings.items.map(item => [item.key, item.poolKey])),
          domainPoolOrder: fixture.bindings.items.map(item => item.key) });
      }
      if (['/api/check', '/api/check-ip'].includes(url.pathname)) {
        const metrics = fixture.probeMetrics;
        metrics.active++;
        metrics.peak = Math.max(metrics.peak, metrics.active);
        try {
        if (fixture.probeDelay) await new Promise((resolve) => setTimeout(resolve, fixture.probeDelay));
        const address = input.proxyip ?? url.searchParams.get('ip');
        const result = { status: 'alive', exitFamily: 'ipv4', latencyMs: 12, colo: 'SJC', exits: probeExits };
        return url.pathname === '/api/check'
          ? json({ ok: true, input: address, source: { kind: 'direct' }, items: [{ address, result }], skipped: [] })
          : json({ ...mainProbe, responseTime: 12, asn: 'AS64500', country: 'US', stack: 'v4' });
        } finally { metrics.active--; }
      }
      if (['/api/add-record', '/api/add-a-record'].includes(url.pathname)) {
        if (fixture.failRecordSave) { fixture.failRecordSave = false; return json({ success: false, error: '模拟 DNS 添加失败' }, url.pathname === '/api/add-a-record' ? 200 : 500); }
        const target = config.targets.find((target) => `${target.domain}|${target.mode}` === input.target)
          ?? config.targets[input.targetIndex ?? 0];
        if (target.mode !== 'A') return json({ error: '此写入替身仅用于 A/AAAA 添加流程' }, 501);
        const value = input.value ?? input.ip;
        const ipv6 = /^\[([^\]]+)\]/.exec(value);
        fixture.records[`${target.domain}|${target.mode}`].push({ id: `fixture-new-${++fixture.nextRecord}`,
          type: ipv6 ? 'AAAA' : 'A', name: target.domain, content: ipv6?.[1] ?? value.split(':')[0] });
        return json({ ok: true, success: true, mode: target.mode });
      }
      if (url.pathname === '/api/delete-record') {
        const target = config.targets.find((target) => `${target.domain}|${target.mode}` === input.target)
          ?? config.targets[Number(url.searchParams.get('target')) || 0];
        const recordId = input.recordId ?? url.searchParams.get('id');
        const key = `${target.domain}|${target.mode}`;
        fixture.records[key] = fixture.records[key].filter(record => record.id !== recordId);
        return json({ ok: true, success: true });
      }
      if (url.pathname === '/api/current-status') {
        const target = config.targets.find((item) => `${item.domain}|${item.mode}` === url.searchParams.get('target'))
          ?? config.targets[Number(url.searchParams.get('target')) || 0];
        const records = fixture.records[`${target.domain}|${target.mode}`] ?? [];
        return json({ ok: true, domain: target.domain, mode: target.mode, records,
          aRecords: target.mode === 'A' ? records.map((record) => ({ ...record, ip: record.content, port: target.port,
            address: record.type === 'AAAA' ? `[${record.content}]:${target.port}` : `${record.content}:${target.port}`,
            ...mainProbe })) : [],
          txtRecords: target.mode === 'TXT' ? [{ id: records[0].id, ips: ['203.0.113.10:443', '[2001:db8::10]:8443'].map(ip => ({
            ip, ...mainProbe })) }] : [] });
      }
      if (url.pathname === '/api/get-config') return json({ success: true, config });
      if (url.pathname === '/api/get-pool') {
        const text = await kv.get(url.searchParams.get('poolKey') ?? 'ip_pool_default') ?? '';
        const ips = text.split('\n').filter(line => line.trim());
        return json({ success: true, ips, count: ips.length });
      }
      if (url.pathname === '/api/get-domain-pool-mapping') return json({ success: true,
        pools: pools.map((item) => item.key), poolNames: Object.fromEntries(pools.map((item) => [item.key, item.name])),
        mapping: Object.fromEntries(bindings.items.map((item) => [item.key, item.poolKey])), domainPoolOrder: bindings.items.map((item) => item.key),
        ips: ['203.0.113.10:443', '203.0.113.11:443'], count: 2 });
      if (/^\/api\/pools\/[^/]+$/.test(url.pathname)) return json({ key: url.pathname.split('/').pop(), content: '203.0.113.10:443\n203.0.113.11:443', count: 2 });
      return json({ error: `Unmocked UI request: ${request.method} ${url.pathname}` }, 501);
    }
    if (referenceHtml && ['/reference', '/reference-login'].includes(url.pathname)) {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return response.end(url.pathname === '/reference-login' ? referenceLoginHtml : referenceHtml);
    }
    const file = resolve(webRoot, url.pathname === '/' ? 'index.html' : `.${url.pathname}`);
    if (!file.startsWith(webRoot + sep) || !existsSync(file)) { response.writeHead(404); return response.end(); }
    if (url.pathname.includes('/order-dialog-') && fixture.orderChunkDelay) await new Promise(resolve => setTimeout(resolve, fixture.orderChunkDelay));
    response.writeHead(200, { 'content-type': ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] || 'application/octet-stream' });
    response.end(readFileSync(file));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, fixture, requests,
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}
