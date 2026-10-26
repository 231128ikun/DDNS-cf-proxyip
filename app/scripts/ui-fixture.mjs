import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, resolve, sep } from 'node:path';
import { createContext, Script } from 'node:vm';

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
  return { config, pools, bindings, records, nextRecord: 0, failConfigSave: false, failRecordSave: false, probeDelay: 0, configDelay: 0 };
}

export function renderReference(config, ref = UI_REFERENCE_REF) {
  let source;
  try {
    source = execFileSync('git', ['show', `${ref}:_worker.js`], { cwd: appRoot, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    throw new Error(`无法读取 UI 基准 ${ref}；请获取该提交的 Git 历史后再运行验收`);
  }
  const context = createContext({ URL, Response, Request, Headers, AbortController,
    fetch: () => { throw new Error('UI reference cannot access network'); } });
  new Script(source.replace('export default {', 'const referenceWorker = {')).runInContext(context, { timeout: 1000 });
  return context.renderHTML(config, { kvReady: true });
}

/** 本地测试服务器：真实构建页面与 main 渲染器共用虚构配置，所有 API 都被本地替身接住。 */
export async function serveUiFixture({ reference = false, ref = UI_REFERENCE_REF, empty = false } = {}) {
  if (!existsSync(join(webRoot, 'index.html'))) throw new Error('请先运行 npm run build');
  const fixture = createUiFixture();
  if (empty) { fixture.config.zones = []; fixture.config.targets = []; fixture.bindings.items = []; }
  const referenceHtml = reference ? renderReference(fixture.config, ref) : null;
  const requests = [];
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const json = (data, status = 200) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(data)); };
    if (url.pathname.startsWith('/api/')) {
      let body = '';
      for await (const chunk of request) body += chunk;
      const input = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, method: request.method, input,
        surface: request.headers.referer?.includes('/reference') ? 'main' : 'current' });
      const { config, pools, bindings } = fixture;
      const publicConfig = { ...config, zones: config.zones.map(({ apiKey, ...zone }) => ({ ...zone, hasApiKey: Boolean(apiKey) })),
        secrets: { apiKey: Boolean(config.apiKey), tgToken: Boolean(config.tgToken) } };
      delete publicConfig.apiKey;
      delete publicConfig.tgToken;
      if (url.pathname === '/api/health') return json({ ok: true, version: 'fixture', configSource: 'kv' });
      if (url.pathname === '/api/config' && request.method === 'GET') {
        if (fixture.configDelay) await new Promise((resolve) => setTimeout(resolve, fixture.configDelay));
        return json({ source: 'kv', config: publicConfig });
      }
      if (['/api/config', '/api/save-config'].includes(url.pathname) && ['POST', 'PUT'].includes(request.method)) {
        if (fixture.failConfigSave) {
          fixture.failConfigSave = false;
          return json({ success: false, error: '模拟配置保存失败' }, url.pathname === '/api/save-config' ? 200 : 500);
        }
        const update = input.config ?? input;
        Object.assign(config, update, { zones: update.zones.map((zone) => ({ ...zone,
          apiKey: zone.apiKey || config.zones.find((previous) => previous.baseDomain === zone.baseDomain)?.apiKey || '' })) });
        if (url.pathname === '/api/save-config') return json({ success: true, config });
        return json({ source: 'kv', config: { ...config, apiKey: undefined, tgToken: undefined,
          zones: config.zones.map(({ apiKey, ...zone }) => ({ ...zone, hasApiKey: Boolean(apiKey) })), secrets: publicConfig.secrets } });
      }
      if (url.pathname === '/api/pools') return json({ pools });
      if (url.pathname === '/api/domain-bindings') return json(bindings);
      if (['/api/check', '/api/check-ip'].includes(url.pathname)) {
        if (fixture.probeDelay) await new Promise((resolve) => setTimeout(resolve, fixture.probeDelay));
        const address = input.proxyip ?? url.searchParams.get('ip');
        const result = { status: 'alive', exitFamily: 'ipv4', latencyMs: 12, colo: 'SJC', exits: probeExits };
        return url.pathname === '/api/check'
          ? json({ ok: true, input: address, source: { kind: 'direct' }, items: [{ address, result }], skipped: [] })
          : json({ ...mainProbe, responseTime: 12, asn: 'AS64500', country: 'US', stack: 'v4' });
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
      if (['/api/get-pool', '/api/get-domain-pool-mapping'].includes(url.pathname)) return json({ success: true,
        pools: pools.map((item) => item.key), poolNames: Object.fromEntries(pools.map((item) => [item.key, item.name])),
        mapping: Object.fromEntries(bindings.items.map((item) => [item.key, item.poolKey])), domainPoolOrder: bindings.items.map((item) => item.key),
        ips: ['203.0.113.10:443', '203.0.113.11:443'], count: 2 });
      if (/^\/api\/pools\/[^/]+$/.test(url.pathname)) return json({ key: url.pathname.split('/').pop(), content: '203.0.113.10:443\n203.0.113.11:443', count: 2 });
      return json({ error: `Unmocked UI request: ${request.method} ${url.pathname}` }, 501);
    }
    if (referenceHtml && url.pathname === '/reference') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return response.end(referenceHtml);
    }
    const file = resolve(webRoot, url.pathname === '/' ? 'index.html' : `.${url.pathname}`);
    if (!file.startsWith(webRoot + sep) || !existsSync(file)) { response.writeHead(404); return response.end(); }
    response.writeHead(200, { 'content-type': ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' })[extname(file)] || 'application/octet-stream' });
    response.end(readFileSync(file));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, fixture, requests,
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}
