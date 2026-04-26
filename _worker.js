/**
 * DDNS Pro & Proxy IP Manager
 */

// ==================== 默认配置（环境变量未设置时使用） ====================
const DEFAULT_CONFIG = {
    // 目标维护域名的Cloudflare 配置
    apiKey: '',              // CF_KEY: Cloudflare API Token
    zoneId: '',              // CF_ZONEID: Cloudflare Zone ID
    zones: [],               // app_config.zones: 多套基础域名 + CF 凭据
    
    // 目标维护域名的配置
    targets: [],             // CF_DOMAIN: 域名配置（解析后的目标列表）
    
    // Telegram 通知配置
    tgToken: '',             // TG_TOKEN: Telegram Bot Token
    tgId: '',                // TG_ID: Telegram Chat ID
    
    // 检测 API 配置
    checkApi: 'https://api.090227.xyz/check?proxyip=',  // CHECK_API: ProxyIP 检测接口
    checkApiBackup: '',      // CHECK_API_BACKUP: 备用检测接口
    
    // DNS 配置
    dohApi: 'https://cloudflare-dns.com/dns-query',  // DOH_API: DNS over HTTPS 接口
    // 访问控制配置
    authKey: '',             // AUTH_KEY: 面板访问密钥
    scheduledEnabled: true,   // SCHEDULED_ENABLED: 定时维护开关
    tgEnabled: true,          // TG_ENABLED: Telegram 通知开关
    
    // 运行时配置（非环境变量）
    projectUrl: ''           // 项目URL（自动获取）
};
// ==================== 默认配置结束 ====================

const GLOBAL_SETTINGS = {
    // ── IP 检测 ──
    CONCURRENT_CHECKS: 32,       // 前端批量检测并发数（参考检测页实现）
    CHECK_TIMEOUT: 3000,         // 单次 ProxyIP 检测超时(ms)

    // ── 网络超时 ──
    REMOTE_LOAD_TIMEOUT: 5000,   // 远程 URL 加载超时(ms)
    DOH_TIMEOUT: 5000,           // DNS over HTTPS 查询超时(ms)

    // ── 数据限制 ──
    DEFAULT_MIN_ACTIVE: 3,       // 默认最小活跃 IP 数
    MAX_TRASH_SIZE: 1000,        // 垃圾桶最大条目数
    MAX_POOL_NAME_LENGTH: 50,    // IP池名称最大长度
    MAX_IPS_PER_DOMAIN: 50,      // 域名解析最多取多少个 IP
};

const APP_CONFIG_KEY = 'app_config';
const APP_VERSION = '2026.04.26-21.25';

function safeJSONParse(str, defaultValue = null) {
    try { return str ? JSON.parse(str) : defaultValue; }
    catch { return defaultValue; }
}

const parsePoolList = raw => (raw || '').split('\n').filter(l => l.trim());

const parseTXTContent = content => content ? content.replace(/^"|"$/g, '').split(',').map(ip => ip.trim()).filter(Boolean) : [];

const extractIPKey = line => {
    if (!line) return '';
    const main = line.split('#')[0].trim();
    return main.split(',')[0].trim();
};

function extractHostFromAddr(addr) {
    const value = extractIPKey(addr || '');
    if (!value) return '';
    if (value.startsWith('[')) {
        const end = value.indexOf(']');
        return end >= 0 ? value.slice(1, end) : value.replace(/^\[/, '');
    }
    const parts = value.split(':');
    return parts.length > 2 ? value : parts[0];
}

function extractPortFromAddr(addr, defaultPort = '443') {
    const value = extractIPKey(addr || '');
    if (!value) return defaultPort;
    if (value.startsWith('[')) {
        const match = value.match(/\]:(\d+)$/);
        return match ? match[1] : defaultPort;
    }
    const parts = value.split(':');
    return parts.length === 2 ? parts[1] : defaultPort;
}

function isIPv6Address(ip) {
    const value = String(ip || '').replace(/^\[/, '').replace(/\]$/, '');
    return value.includes(':');
}

function getDNSRecordTypeForIP(ip) {
    return isIPv6Address(ip) ? 'AAAA' : 'A';
}

function formatAddr(ip, port = '443') {
    const cleanIP = String(ip || '').replace(/^\[/, '').replace(/\]$/, '');
    return isIPv6Address(cleanIP) ? `[${cleanIP}]:${port}` : `${cleanIP}:${port}`;
}

function splitComment(line) {
    if (!line) return { main: '', comment: '' };
    const idx = line.indexOf('#');
    if (idx >= 0) return { main: line.substring(0, idx).trim(), comment: line.substring(idx) };
    return { main: line.trim(), comment: '' };
}

function parsePoolEntry(line) {
    const raw = String(line || '').trim();
    if (!raw) return null;
    const beforeComment = raw.split('#')[0].trim();
    const fields = beforeComment.split(',').map(item => item.trim());
    const address = fields[0] || '';
    if (!address) return null;
    const legacyComment = raw.includes('#') ? raw.slice(raw.indexOf('#') + 1).trim() : '';
    return {
        address,
        asn: fields[1] || null,
        country: fields[2] || null,
        stack: normalizeStackFilter(fields[3] || null),
        legacyComment
    };
}

function normalizeStackFilter(value) {
    const text = String(value || '').trim().toLowerCase().replace(/_/g, '-');
    if (!text) return 'v4/v6';
    if (['v4', 'ipv4', 'ipv4-only', 'only-ipv4'].includes(text)) return 'v4';
    if (['v6', 'ipv6', 'ipv6-only', 'only-ipv6'].includes(text)) return 'v6';
    if (['v4/v6', 'v6/v4', 'dual', 'dual-stack', 'both', 'all', 'ipv4-ipv6'].includes(text)) return 'v4/v6';
    return text.replace('-', '_');
}

const POOL_DISPLAY_NAMES = { pool: '通用池', pool_trash: '🗑️ 垃圾桶', domain_pool_mapping: '系统数据' };
const getPoolDisplayName = poolKey => POOL_DISPLAY_NAMES[poolKey] || poolKey.replace('pool_', '') + '池';

const formatLogMessage = msg => `[${new Date().toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' })}] ${msg}`;

const JSON_CONTENT_TYPE = 'application/json; charset=UTF-8';
const CF_ERROR_MSG = 'CF配置错误或API调用失败';

function jsonResponse(data, status = 200, extraHeaders = undefined) {
    const headers = new Headers({ 'Content-Type': JSON_CONTENT_TYPE });
    if (extraHeaders) {
        const h = extraHeaders instanceof Headers ? extraHeaders : new Headers(extraHeaders);
        h.forEach((v, k) => headers.set(k, v));
    }
    return new Response(JSON.stringify(data), { status, headers });
}

const badRequest = data => jsonResponse(data, 400);
const serverError = data => jsonResponse(data, 500);
const readJsonBody = async req => { try { return await req.json(); } catch { return null; } };
const hasKVBinding = env => Boolean(env?.IP_DATA && typeof env.IP_DATA.get === 'function' && typeof env.IP_DATA.put === 'function');

function parseCookieHeader(cookieHeader) {
    const out = {};
    if (!cookieHeader) return out;
    cookieHeader.split(';').forEach(part => {
        const idx = part.indexOf('=');
        if (idx === -1) return;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (k) { try { out[k] = decodeURIComponent(v); } catch { out[k] = v; } }
    });
    return out;
}

function getAuthCandidateFromRequest(request, url) {
    const authHeader = request.headers.get('Authorization') ?? '';
    const bearer = authHeader.toLowerCase().startsWith('bearer ')
        ? authHeader.slice(7).trim()
        : '';
    const xAuth = (request.headers.get('X-Auth-Key') ?? '').trim();
    const qKey = (url.searchParams.get('key') ?? '').trim();
    const cookies = parseCookieHeader(request.headers.get('Cookie') ?? '');
    const cKey = (cookies.ddns_auth ?? '').trim();
    return { bearer, xAuth, qKey, cKey };
}

function checkRequestAuth(request, url, config) {
    const requiredKey = (config.authKey || '').trim();
    if (!requiredKey) {
        return { enabled: false, ok: true, shouldSetCookie: false };
    }

    const { bearer, xAuth, qKey, cKey } = getAuthCandidateFromRequest(request, url);
    const ok = bearer === requiredKey || xAuth === requiredKey || qKey === requiredKey || cKey === requiredKey;
    const shouldSetCookie = ok && qKey === requiredKey && cKey !== requiredKey;
    return { enabled: true, ok, shouldSetCookie };
}

function unauthorizedResponse(url) {
    const isApi = url.pathname.startsWith('/api/');
    if (isApi) {
        return jsonResponse({
            success: false,
            error: '未授权',
            message: '需要提供 AUTH_KEY'
        }, 401);
    }
    // 页面：给出最小可理解指引
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DDNS Pro - 未授权</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0b0b0f;color:#eaeaf2;margin:0;padding:40px}
    .card{max-width:760px;margin:0 auto;background:#151523;border:1px solid #2a2a40;border-radius:16px;padding:24px}
    code{background:#0f0f1a;padding:2px 6px;border-radius:8px}
    a{color:#7aa2ff}
  </style>
</head>
<body>
  <div class="card">
    <h2>未授权</h2>
    <p>该面板已开启访问保护（配置了 <code>AUTH_KEY</code>）。</p>
    <p>打开方式示例：<code>/?key=你的AUTH_KEY</code>（首次访问会写入 Cookie，后续可直接打开）。</p>
  </div>
</body>
</html>`;
    return new Response(html, { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

export default {
    async fetch(request, env, ctx) {
        const requestStart = Date.now();
        const url = new URL(request.url);
        const config = await createConfig(env, request);
        const kvReady = hasKVBinding(env);

        const buildAuthCookie = () => `ddns_auth=${encodeURIComponent((config.authKey || '').trim())}; Path=/; HttpOnly; Secure; SameSite=Lax`;

        // 可选鉴权：不配置 AUTH_KEY 时跳过
        const auth = checkRequestAuth(request, url, config);
        if (auth.enabled && !auth.ok && url.pathname !== '/favicon.ico') {
            return unauthorizedResponse(url);
        }

        if (url.pathname === '/') {
            const html = renderHTML(config, { kvReady });
            console.log(`📄 首页请求处理耗时: ${Date.now() - requestStart}ms`);
            const headers = new Headers({ 'Content-Type': 'text/html;charset=UTF-8' });
            // 首页不缓存（含动态配置），但允许浏览器在后退时使用缓存
            headers.set('Cache-Control', 'no-store');
            if (auth.shouldSetCookie) {
                headers.set('Set-Cookie', buildAuthCookie());
            }
            return new Response(html, { headers });
        }

        if (url.pathname === '/favicon.ico') {
            return new Response(null, { status: 204 });
        }

        try {
            if (url.pathname.startsWith('/api/') && !kvReady) {
                return serverError({
                    success: false,
                    error: 'KV 未绑定',
                    message: '请在 Worker Settings > Bindings 中绑定 KV Namespace，变量名必须为 IP_DATA。'
                });
            }
            const apiStart = Date.now();
            const response = await handleAPIRequest(url, request, env, config);
            console.log(`🔧 API请求 ${url.pathname} 处理耗时: ${Date.now() - apiStart}ms`);

            // 添加性能头信息
            const headers = new Headers(response.headers);
            headers.set('X-Processing-Time', `${Date.now() - requestStart}ms`);
            if (url.pathname.startsWith('/api/') && !headers.has('Content-Type')) {
                headers.set('Content-Type', 'application/json; charset=UTF-8');
            }
            // API 响应不缓存，确保数据实时性
            if (url.pathname.startsWith('/api/')) {
                headers.set('Cache-Control', 'no-store');
            }
            if (auth.shouldSetCookie) {
                headers.set('Set-Cookie', buildAuthCookie());
            }

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers
            });
        } catch (e) {
            console.error(`❌ 请求处理失败 ${url.pathname}:`, e);
            return serverError({
                error: '内部服务器错误',
                message: '请稍后重试'
            });
        }
    },

    async scheduled(event, env, ctx) {
        console.log('⏰ 定时任务开始执行');
        const startTime = Date.now();

        try {
            if (!hasKVBinding(env)) {
                console.error('❌ KV 未绑定：请绑定变量名为 IP_DATA 的 KV Namespace，定时维护已跳过');
                return;
            }
            const config = await createConfig(env);
            if (!config.scheduledEnabled) {
                console.log('⏸️ 定时维护已关闭，跳过执行');
                return;
            }
            ctx.waitUntil((async () => {
                await maintainAllDomains(env, false, config);
                console.log(`✅ 定时任务完成，总耗时: ${Date.now() - startTime}ms`);
            })());
        } catch (e) {
            console.error('❌ 定时任务失败:', e);
        }
    }
};

const API_ROUTES = {
    '/api/get-pool': (url, req, env, config) => handleGetPool(url, env),
    '/api/save-pool': (url, req, env, config) => handleSavePool(req, env, config),
    '/api/load-remote-url': (url, req, env, config) => handleLoadRemoteUrl(req),
    '/api/current-status': (url, req, env, config) => handleCurrentStatus(url, config),
    '/api/lookup-domain': (url, req, env, config) => handleLookupDomain(url, config),
    '/api/check-ip': (url, req, env, config) => handleCheckIP(url, config),
    '/api/delete-record': (url, req, env, config) => handleDeleteRecord(url, config),
    '/api/add-a-record': (url, req, env, config) => handleAddARecord(req, config),
    '/api/maintain': (url, req, env, config) => handleMaintain(url, env, config),
    '/api/get-domain-pool-mapping': (url, req, env, config) => handleGetDomainPoolMapping(env),
    '/api/save-domain-pool-mapping': (url, req, env, config) => handleSaveDomainPoolMapping(req, env),
    '/api/create-pool': (url, req, env, config) => handleCreatePool(req, env),
    '/api/delete-pool': (url, req, env, config) => handleDeletePool(url, env),
    '/api/clear-trash': (url, req, env, config) => handleClearTrash(env),
    '/api/restore-from-trash': (url, req, env, config) => handleRestoreFromTrash(req, env),
    '/api/get-config': (url, req, env, config) => handleGetConfig(config),
    '/api/save-config': (url, req, env, config) => handleSaveConfig(req, env)
};

const POST_ONLY_ROUTES = new Set([
    '/api/save-pool', '/api/load-remote-url', '/api/add-a-record',
    '/api/save-domain-pool-mapping', '/api/create-pool', '/api/clear-trash',
    '/api/restore-from-trash',
    '/api/delete-record',
    '/api/delete-pool', 
    '/api/maintain',
    '/api/save-config'
]);

async function handleAPIRequest(url, request, env, config) {
    if (POST_ONLY_ROUTES.has(url.pathname) && request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }
    const handler = API_ROUTES[url.pathname];
    return handler ? await handler(url, request, env, config) : new Response('Not Found', { status: 404 });
}

async function handleGetPool(url, env) {
    const poolKey = url.searchParams.get('poolKey') || 'pool';
    const onlyCount = url.searchParams.get('onlyCount') === 'true';
    
    const pool = await env.IP_DATA.get(poolKey) || '';
    const count = pool.trim() ? pool.trim().split('\n').length : 0;
    
    if (onlyCount) {
        return jsonResponse({ count });
    }
    return jsonResponse({ pool, count });
}

async function handleSavePool(request, env, config) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const poolKey = body.poolKey || 'pool';
    const mode = body.mode || 'append'; // append: 追加, replace: 覆盖, remove: 删除
    const newIPs = await cleanIPListAsync(body.pool || '', false, config);

    if (!newIPs && mode !== 'remove') {
        return badRequest({ success: false, error: '没有有效IP' });
    }

    const existingPool = await env.IP_DATA.get(poolKey) || '';
    const existingMap = new Map();

    // 先加载现有IP
    parsePoolList(existingPool).forEach(line => {
        const key = extractIPKey(line);
        if (key) existingMap.set(key, line);
    });

    const existingCount = existingMap.size;
    let responseData;

    if (mode === 'replace') {
        // 覆盖模式：清空现有，只保留新IP
        existingMap.clear();
        parsePoolList(newIPs).forEach(line => {
            const key = extractIPKey(line);
            if (key) existingMap.set(key, line);
        });

        responseData = {
            success: true,
            count: existingMap.size,
            replaced: existingCount,
            message: `已覆盖，原有 ${existingCount} 个IP，现有 ${existingMap.size} 个IP`
        };
    } else if (mode === 'remove') {
        // 删除模式：从池中删除指定IP
        const toRemove = new Set();
        parsePoolList(newIPs || body.pool || '').forEach(line => {
            const key = extractIPKey(line);
            if (key) toRemove.add(key);
        });

        let removed = 0;
        for (const key of toRemove) {
            if (existingMap.has(key)) {
                existingMap.delete(key);
                removed++;
            }
        }

        responseData = {
            success: true,
            count: existingMap.size,
            removed,
            message: `已删除 ${removed} 个IP，剩余 ${existingMap.size} 个IP`
        };
    } else {
        // 追加模式
        parsePoolList(newIPs).forEach(line => {
            const key = extractIPKey(line);
            if (key) existingMap.set(key, line);
        });

        responseData = {
            success: true,
            count: existingMap.size,
            added: existingMap.size - existingCount
        };
    }

    const finalPool = Array.from(existingMap.values()).join('\n');
    await env.IP_DATA.put(poolKey, finalPool);

    return jsonResponse(responseData);
}

async function handleLoadRemoteUrl(request) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const url = body.url;
    if (!url) {
        return badRequest({ success: false, error: '缺少URL' });
    }
    const ips = await loadFromRemoteUrl(url);
    return jsonResponse({ 
        success: true, 
        ips,
        count: ips ? ips.split('\n').length : 0
    });
}

async function handleCurrentStatus(url, config) {
    const targetIndex = parseInt(url.searchParams.get('target') || '0');
    const target = config.targets[targetIndex];
    if (!target) {
        return badRequest({ error: '无效的目标' });
    }
    const status = await getDomainStatus(target, config);
    return jsonResponse(status);
}

async function handleLookupDomain(url, config) {
    const input = url.searchParams.get('domain');
    if (!input) return badRequest({ error: '缺少domain参数' });

    if (input.startsWith('txt@')) {
        const domain = input.substring(4);
        const txtData = await resolveTXTRecord(domain, config);
        return jsonResponse({
            type: 'TXT',
            domain,
            ips: txtData.ips,
            raw: txtData.raw
        });
    }

    const { domain, port } = parseDomainPort(input);
    const records = await resolveDomainRecords(domain, config);
    const ips = records.map(record => record.ip);
    return jsonResponse({
        type: 'ADDRESS',
        ips,
        records,
        port,
        domain
    });
}

async function handleCheckIP(url, config) {
    const target = url.searchParams.get('ip');
    if (!target) return badRequest({ error: '缺少ip参数' });
    const useBackup = url.searchParams.get('useBackup') === 'true';
    if (useBackup && config.checkApiBackup) {
        const addr = normalizeCheckAddr(target);
        const result = await checkProxyIPOnce(addr, config.checkApiBackup);
        return jsonResponse(result ?? { success: false });
    }
    const res = await checkProxyIP(target, config);
    return jsonResponse(res);
}

async function handleDeleteRecord(url, config) {
    const id = url.searchParams.get('id');
    if (!id) return badRequest({ error: '缺少id参数' });
    const ip = url.searchParams.get('ip');
    const isTxt = url.searchParams.get('isTxt') === 'true';
    const targetIndex = parseInt(url.searchParams.get('target') || '0', 10);
    const cfConfig = getTargetCFConfig(config, config.targets[targetIndex] || null);

    if (isTxt && ip) {
        // TXT记录删除单个IP
        const record = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`);
        if (!record) {
            return badRequest({ success: false, error: '获取记录失败' });
        }

        let ips = parseTXTContent(record.content);

        // 移除指定IP
        ips = ips.filter(i => i !== ip);

        if (ips.length === 0) {
            // 如果没有IP了，删除整个TXT记录
            const result = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`, 'DELETE');
            if (result === null) {
                return jsonResponse({ success: false, error: 'CF API 删除失败' });
            }
        } else {
            // 更新TXT记录
            const newContent = `"${ips.join(',')}"`;
            const result = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`, 'PUT', {
                type: 'TXT',
                name: record.name,
                content: newContent,
                ttl: 60
            });
            if (result === null) {
                return jsonResponse({ success: false, error: 'CF API 更新失败' });
            }
        }

        return jsonResponse({ success: true });
    }
    
    // 地址记录删除
    const result = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`, 'DELETE');
    if (result === null) {
        return jsonResponse({ success: false, error: 'CF API 删除失败' });
    }
    return jsonResponse({ success: true });
}

async function handleAddARecord(request, config) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const ip = body.ip;
    const targetIndex = body.targetIndex || 0;
    const target = config.targets[targetIndex];
    const cfConfig = getTargetCFConfig(config, target);

    if (!ip || !target) {
        return badRequest({ success: false, error: '参数错误' });
    }

    // 格式化IP:PORT
    const addr = ip.includes(':') ? ip : `${ip}:${target.port}`;

    const check = await checkProxyIP(addr, config);
    if (!check.success) {
        return jsonResponse({ success: false, error: 'IP检测失败' });
    }

    // TXT模式：追加到TXT记录
    if (target.mode === 'TXT') {
        const records = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=TXT`);

        if (records === null) {
            return jsonResponse({ success: false, error: CF_ERROR_MSG });
        }

        let currentIPs = [];
        let recordId = null;

        if (records?.length > 0) {
            recordId = records[0].id;
            currentIPs = parseTXTContent(records[0].content);
        }

        // 检查是否已存在
        if (currentIPs.includes(addr)) {
            return jsonResponse({ success: false, error: 'IP已存在于TXT记录' });
        }

        // 追加新IP
        currentIPs.push(addr);
        const newContent = `"${currentIPs.join(',')}"`;

        if (recordId) {
            const putResult = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${recordId}`, 'PUT', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
            if (putResult === null) {
                return jsonResponse({ success: false, error: 'CF API 更新TXT记录失败' });
            }
        } else {
            const postResult = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records`, 'POST', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
            if (postResult === null) {
                return jsonResponse({ success: false, error: 'CF API 创建TXT记录失败' });
            }
        }

        return jsonResponse({
            success: true,
            colo: check.colo,
            time: check.responseTime,
            mode: 'TXT'
        });
    }

    // 地址记录模式
    const content = extractHostFromAddr(ip);
    const recordType = getDNSRecordTypeForIP(content);
    const result = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records`, 'POST', {
        type: recordType,
        name: target.domain,
        content,
        ttl: 60,
        proxied: false
    });

    return jsonResponse({
        success: !!result,
        colo: check.colo,
        time: check.responseTime,
        mode: recordType
    });
}

async function handleMaintain(url, env, config) {
    const isManual = url.searchParams.get('manual') === 'true';
    const res = await maintainAllDomains(env, isManual, config);

    // 将日志包含在响应中
    return jsonResponse({
        ...res,
        // 确保所有日志都返回给前端
        allLogs: res.reports.flatMap(r => [
            ...(r.logs || []),
            ...(r.txtLogs || [])
        ])
    });
}

async function handleGetDomainPoolMapping(env) {
    const mappingJson = await env.IP_DATA.get('domain_pool_mapping') || '{}';
    const mapping = safeJSONParse(mappingJson, {});
    
    const allKeys = await env.IP_DATA.list();
    const pools = allKeys.keys
        .filter(k => k.name.startsWith('pool'))
        .map(k => k.name);
    
    if (!pools.includes('pool')) {
        pools.unshift('pool');
    }
    
    return jsonResponse({ mapping, pools });
}

async function handleSaveDomainPoolMapping(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    await env.IP_DATA.put('domain_pool_mapping', JSON.stringify(body.mapping));
    return jsonResponse({ success: true });
}

async function handleCreatePool(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const poolKey = body.poolKey;
    
    if (!poolKey || !poolKey.startsWith('pool_')) {
        return badRequest({ success: false, error: '池名称必须以pool_开头' });
    }
    
    // 支持中文、字母、数字、下划线、横杠
    if (poolKey.length > GLOBAL_SETTINGS.MAX_POOL_NAME_LENGTH || !/^pool_[\u4e00-\u9fa5a-zA-Z0-9_-]+$/.test(poolKey)) {
        return badRequest({ success: false, error: `池名称只能包含中文、字母、数字、下划线、横杠，最长${GLOBAL_SETTINGS.MAX_POOL_NAME_LENGTH}字符` });
    }
    
    const existing = await env.IP_DATA.get(poolKey);
    if (existing !== null) {
        return badRequest({ success: false, error: '池已存在' });
    }
    
    await env.IP_DATA.put(poolKey, '');
    return jsonResponse({ success: true });
}

async function handleDeletePool(url, env) {
    const poolKey = url.searchParams.get('poolKey');
    
    if (!poolKey) {
        return badRequest({ success: false, error: '缺少poolKey参数' });
    }
    
    // 保护系统池
    const protectedPools = ['pool', 'domain_pool_mapping', 'pool_trash'];
    if (protectedPools.includes(poolKey)) {
        return badRequest({ success: false, error: `不能删除${getPoolDisplayName(poolKey)}` });
    }
    
    try {
        await env.IP_DATA.delete(poolKey);
        return jsonResponse({ success: true });
    } catch (e) {
        console.error('删除池失败:', e);
        return jsonResponse({ success: false, error: '删除池失败' });
    }
}

async function handleClearTrash(env) {
    await env.IP_DATA.put('pool_trash', '');
    return jsonResponse({ success: true, message: '垃圾桶已清空' });
}

async function handleRestoreFromTrash(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const ipsToRestore = body.ips || [];
    const restoreToSource = body.restoreToSource === true;
    const targetPool = body.targetPool || 'pool';
    
    if (ipsToRestore.length === 0) {
        return badRequest({ success: false, error: '没有选择IP' });
    }
    
    // 获取垃圾桶
    let trashList = parsePoolList(await env.IP_DATA.get('pool_trash'));
    
    let restored = 0;
    const restoredByPool = {};

    // 读取/写入多个池：按需懒加载
    const poolCache = new Map(); // poolKey -> { list: string[], set: Set<string> }
    async function loadPool(poolKey) {
        if (poolCache.has(poolKey)) return poolCache.get(poolKey);
        const list = parsePoolList(await env.IP_DATA.get(poolKey));
        const set = new Set(list.map(p => extractIPKey(p)));
        const obj = { list, set };
        poolCache.set(poolKey, obj);
        return obj;
    }

    // 从垃圾桶条目中提取来源池
    function pickTargetPoolFromTrashEntry(trashEntry) {
        if (!restoreToSource) return targetPool;
        // trashEntry 格式：`${ipAddr} # ${reason} ${timestamp} 来自 ${poolKey}`
        // 例如：`1.2.3.4:443 # 洗库失效 2024-01-01T00:00:00.000Z 来自 pool_a`
        const idx = trashEntry.lastIndexOf(' 来自 ');
        if (idx !== -1) {
            const sourcePool = trashEntry.slice(idx + 4).trim();
            // 直接返回来源池名（如 pool_a），不需要通过域名映射
            if (sourcePool && sourcePool.startsWith('pool')) {
                return sourcePool;
            }
        }
        return 'pool';
    }
    
    // 建立垃圾桶索引，避免循环内反复遍历
    const trashMap = new Map();
    trashList.forEach(t => trashMap.set(extractIPKey(t), t));

    // 恢复IP
    for (const ip of ipsToRestore) {
        const trashEntry = trashMap.get(ip);

        if (trashEntry) {
            trashMap.delete(ip);

            const toPool = pickTargetPoolFromTrashEntry(trashEntry);
            const poolObj = await loadPool(toPool);

            // 添加到目标池（如果不存在）- 只恢复纯净的IP:PORT，不携带垃圾桶注释
            if (!poolObj.set.has(ip)) {
                poolObj.list.push(ip);
                poolObj.set.add(ip);
                restored++;
                restoredByPool[toPool] = (restoredByPool[toPool] || 0) + 1;
            }
        }
    }

    // 保存
    await env.IP_DATA.put('pool_trash', Array.from(trashMap.values()).join('\n'));
    for (const [poolKey, poolObj] of poolCache.entries()) {
        await env.IP_DATA.put(poolKey, poolObj.list.join('\n'));
    }
    
    return jsonResponse({ 
        success: true, 
        restored,
        restoredByPool,
        message: restoreToSource
            ? `已恢复 ${restored} 个IP到源IP库`
            : `已恢复 ${restored} 个IP到 ${targetPool}`
    });
}

function getEditableConfig(config) {
    return {
        apiKey: config.apiKey || '',
        zoneId: config.zoneId || '',
        zones: config.zones || [],
        targets: config.targets || [],
        tgToken: config.tgToken || '',
        tgId: config.tgId || '',
        tgEnabled: config.tgEnabled !== false,
        checkApi: config.checkApi || '',
        checkApiBackup: config.checkApiBackup || '',
        dohApi: config.dohApi || '',
        authKey: config.authKey || '',
        scheduledEnabled: config.scheduledEnabled !== false,
        settings: { ...GLOBAL_SETTINGS }
    };
}

async function handleGetConfig(config) {
    return jsonResponse({ success: true, config: getEditableConfig(config) });
}

async function handleSaveConfig(request, env) {
    const body = await readJsonBody(request);
    if (!body || typeof body !== 'object') {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }

    const rawConfig = body.config && typeof body.config === 'object' ? body.config : body;
    const normalized = normalizeSavedConfig(rawConfig);
    await env.IP_DATA.put(APP_CONFIG_KEY, JSON.stringify(normalized));
    return jsonResponse({ success: true, config: normalized });
}

function parseDomainPort(input, defaultPort = '443') {
    if (!input) return { domain: '', port: defaultPort };
    input = input.trim();
    if (input.startsWith('[')) {
        const end = input.indexOf(']');
        const domain = end >= 0 ? input.slice(1, end) : input.replace(/^\[/, '');
        const match = input.match(/\]:(\d+)$/);
        return { domain, port: match ? match[1] : defaultPort };
    }
    const parts = input.split(':');
    if (parts.length > 2) return { domain: input, port: defaultPort };
    return {
        domain: parts[0],
        port: parts[1] || defaultPort
    };
}

function parseBooleanConfig(value, defaultValue = true) {
    if (value === undefined || value === null || value === '') return defaultValue;
    if (typeof value === 'boolean') return value;
    const text = String(value).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on', 'enabled'].includes(text)) return true;
    if (['0', 'false', 'no', 'off', 'disabled'].includes(text)) return false;
    return defaultValue;
}

function normalizeTargetMode(value) {
    const text = String(value || 'A').trim().toUpperCase();
    if (text === 'TXT') return 'TXT';
    return 'A';
}

function normalizeExitFilter(value) {
    const text = String(value || '').trim().toLowerCase().replace(/_/g, '-');
    if (!text || ['any', 'all', 'v4/v6', 'v6/v4'].includes(text)) return 'any';
    if (['v4', 'ipv4', 'ipv4-only', 'only-ipv4'].includes(text)) return 'v4';
    if (['v6', 'ipv6', 'ipv6-only', 'only-ipv6'].includes(text)) return 'v6';
    if (['dual', 'dual-stack', 'both'].includes(text)) return 'dual';
    return 'any';
}

function stackToExitFilter(stack) {
    const normalized = normalizeStackFilter(stack);
    if (normalized === 'v4') return 'v4';
    if (normalized === 'v6') return 'v6';
    return 'any';
}

function normalizeTargetConfig(target) {
    if (!target || typeof target !== 'object') return null;
    const baseDomain = String(target.baseDomain || '').trim();
    const prefix = String(target.prefix || '').trim().replace(/^\.+|\.+$/g, '');
    const domain = String(target.domain || buildManagedDomain(prefix, baseDomain)).trim();
    if (!domain) return null;
    const mode = normalizeTargetMode(target.mode);
    const port = String(target.port || '443').trim() || '443';
    const minActive = Math.max(0, parseInt(target.minActive ?? GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE, 10) || GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE);
    const exitFilter = normalizeExitFilter(target.exitFilter || target.stack);
    const country = String(target.country || '').trim().toUpperCase();
    const asn = normalizeAsnValue(target.asn);
    const zoneIndex = Number.isInteger(target.zoneIndex) ? target.zoneIndex : (target.zoneIndex === '' || target.zoneIndex === undefined ? null : parseInt(target.zoneIndex, 10));
    const enabled = target.enabled !== false;
    return {
        mode,
        domain,
        baseDomain,
        prefix,
        zoneIndex: Number.isInteger(zoneIndex) && zoneIndex >= 0 ? zoneIndex : null,
        port,
        minActive,
        exitFilter,
        country,
        asn,
        enabled
    };
}

function buildManagedDomain(prefix, baseDomain) {
    const cleanPrefix = String(prefix || '').trim().replace(/^\.+|\.+$/g, '');
    const cleanBase = String(baseDomain || '').trim().replace(/^\.+|\.+$/g, '');
    if (!cleanBase) return '';
    return cleanPrefix ? `${cleanPrefix}.${cleanBase}` : cleanBase;
}

function inferBaseDomainFromTargets(targets) {
    const domains = (Array.isArray(targets) ? targets : [])
        .map(target => String(target?.domain || '').trim().toLowerCase())
        .filter(Boolean);
    if (domains.length === 0) return '';

    const splitDomains = domains.map(domain => domain.split('.').filter(Boolean));
    if (splitDomains.length === 1) {
        const labels = splitDomains[0];
        return labels.length > 2 ? labels.slice(-3).join('.') : labels.join('.');
    }

    const firstReversed = [...splitDomains[0]].reverse();
    const common = [];
    for (let i = 0; i < firstReversed.length; i++) {
        const label = firstReversed[i];
        if (splitDomains.every(parts => [...parts].reverse()[i] === label)) {
            common.push(label);
        } else {
            break;
        }
    }
    return common.length >= 2 ? common.reverse().join('.') : '';
}

function applyZoneDefaultsFromTargets(config) {
    if (!config || !Array.isArray(config.targets)) return config;
    if (!Array.isArray(config.zones)) config.zones = [];

    const inferredBase = inferBaseDomainFromTargets(config.targets);
    if (config.zones.length === 0 && (config.apiKey || config.zoneId || inferredBase)) {
        config.zones = [{ baseDomain: inferredBase, zoneId: config.zoneId, apiKey: config.apiKey, label: inferredBase || '配置1' }];
    }
    if (config.zones.length > 0 && !config.zones[0].baseDomain && inferredBase) {
        config.zones[0] = { ...config.zones[0], baseDomain: inferredBase, label: config.zones[0].label || inferredBase };
    }

    config.targets = config.targets.map(target => {
        const zoneIndex = Number.isInteger(target.zoneIndex) && target.zoneIndex >= 0 ? target.zoneIndex : 0;
        const zone = config.zones[zoneIndex] || config.zones[0] || {};
        const baseDomain = target.baseDomain || zone.baseDomain || '';
        const prefix = target.prefix || inferPrefixFromDomainValue(target.domain, baseDomain);
        return { ...target, zoneIndex, baseDomain, prefix };
    });
    return config;
}

function inferPrefixFromDomainValue(domain, baseDomain) {
    const d = String(domain || '').trim();
    const b = String(baseDomain || '').trim();
    if (!d || !b || d === b || !d.endsWith('.' + b)) return '';
    return d.slice(0, -(b.length + 1));
}

function normalizeZoneConfig(zone) {
    if (!zone || typeof zone !== 'object') return null;
    const baseDomain = String(zone.baseDomain || zone.domain || '').trim().replace(/^\.+|\.+$/g, '');
    const zoneId = String(zone.zoneId || '').trim();
    const apiKey = String(zone.apiKey || '').trim();
    const name = String(zone.name || '').trim();
    if (!baseDomain && !zoneId && !apiKey) return null;
    return { name, baseDomain, zoneId, apiKey, label: String(zone.label || baseDomain || name || zoneId || '未命名').trim() };
}

function parseTarget(input) {
    if (!input) return null;
    
    input = input.trim();
    let stack = 'v4/v6';
    const stackMatch = input.match(/\|(v4\/v6|v6\/v4|v4|v6|ipv4_only|ipv6_only|dual_stack)$/i);
    if (stackMatch) {
        stack = normalizeStackFilter(stackMatch[1]);
        input = input.slice(0, stackMatch.index).trim();
    }
    
    // 解析最小活跃数（&后面的数字）
    let minActive = GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE;
    const minActiveMatch = input.match(/&(\d+)$/);
    if (minActiveMatch) {
        minActive = parseInt(minActiveMatch[1]);
        input = input.replace(/&\d+$/, ''); // 移除&数字部分
    }
    
    // TXT模式
    if (input.startsWith('txt@')) {
        const rest = input.substring(4);
        const { domain, port } = parseDomainPort(rest);
        return { mode: 'TXT', domain, port, minActive, stack, exitFilter: stackToExitFilter(stack) };
    }
    
    // ALL模式在 createConfig 中拆成地址记录和 TXT 两个目标，这里保留标记用于兼容旧配置
    if (input.startsWith('all@')) {
        const rest = input.substring(4);
        const { domain, port } = parseDomainPort(rest);
        return { mode: 'ALL', domain, port, minActive, stack, exitFilter: stackToExitFilter(stack) };
    }
    
    // 地址记录模式（默认）
    const { domain, port } = parseDomainPort(input);
    return { mode: 'A', domain, port, minActive, stack, exitFilter: stackToExitFilter(stack) };
}

function expandLegacyTargets(targets) {
    const expanded = [];
    for (const target of targets || []) {
        if (!target) continue;
        if (target.mode === 'ALL') {
            expanded.push({ ...target, mode: 'A' }, { ...target, mode: 'TXT' });
        } else {
            expanded.push(target);
        }
    }
    return expanded.map(normalizeTargetConfig).filter(Boolean);
}

function normalizeSavedConfig(rawConfig = {}) {
    const zones = Array.isArray(rawConfig.zones)
        ? rawConfig.zones.map(normalizeZoneConfig).filter(Boolean)
        : [];
    const targets = Array.isArray(rawConfig.targets)
        ? rawConfig.targets.map(normalizeTargetConfig).filter(Boolean)
        : [];
    return {
        apiKey: String(rawConfig.apiKey || '').trim(),
        zoneId: String(rawConfig.zoneId || '').trim(),
        zones,
        targets,
        tgToken: String(rawConfig.tgToken || '').trim(),
        tgId: String(rawConfig.tgId || '').trim(),
        tgEnabled: parseBooleanConfig(rawConfig.tgEnabled, true),
        checkApi: String(rawConfig.checkApi || '').trim(),
        checkApiBackup: String(rawConfig.checkApiBackup || '').trim(),
        dohApi: String(rawConfig.dohApi || '').trim(),
        authKey: String(rawConfig.authKey || '').trim(),
        scheduledEnabled: parseBooleanConfig(rawConfig.scheduledEnabled, true)
    };
}

async function loadSavedConfig(env) {
    try {
        const raw = await env.IP_DATA.get(APP_CONFIG_KEY);
        if (!raw) return null;
        return normalizeSavedConfig(safeJSONParse(raw, {}));
    } catch {
        return null;
    }
}

async function createConfig(env, request = null) {
    const config = { ...DEFAULT_CONFIG };

    config.apiKey = env.CF_KEY || DEFAULT_CONFIG.apiKey;
    config.zoneId = env.CF_ZONEID || DEFAULT_CONFIG.zoneId;
    const envBaseDomain = String(env.CF_BASE_DOMAIN || '').trim();
    config.zones = (config.apiKey || config.zoneId || envBaseDomain)
        ? [{ baseDomain: envBaseDomain, zoneId: config.zoneId, apiKey: config.apiKey, label: envBaseDomain || '环境变量配置' }]
        : [];
    config.authKey = env.AUTH_KEY || DEFAULT_CONFIG.authKey;

    const domainsInput = env.CF_DOMAIN || '';
    if (domainsInput) {
        const parts = domainsInput.split(',').map(s => s.trim()).filter(s => s);
        config.targets = expandLegacyTargets(parts.map(parseTarget).filter(t => t !== null));
    }

    applyZoneDefaultsFromTargets(config);

    if (config.targets.length === 0) {
        config.targets = [];
    }

    config.tgToken = env.TG_TOKEN || DEFAULT_CONFIG.tgToken;
    config.tgId = env.TG_ID || DEFAULT_CONFIG.tgId;
    config.tgEnabled = parseBooleanConfig(env.TG_ENABLED, DEFAULT_CONFIG.tgEnabled);
    config.checkApi = env.CHECK_API || DEFAULT_CONFIG.checkApi;
    config.checkApiBackup = env.CHECK_API_BACKUP || DEFAULT_CONFIG.checkApiBackup;
    config.dohApi = env.DOH_API || DEFAULT_CONFIG.dohApi;
    config.scheduledEnabled = parseBooleanConfig(env.SCHEDULED_ENABLED, DEFAULT_CONFIG.scheduledEnabled);

    const savedConfig = await loadSavedConfig(env);
    if (savedConfig) {
        for (const key of ['apiKey', 'zoneId', 'tgToken', 'tgId', 'checkApi', 'checkApiBackup', 'dohApi', 'authKey']) {
            if (savedConfig[key]) config[key] = savedConfig[key];
        }
        if (savedConfig.zones.length > 0) {
            config.zones = savedConfig.zones;
            config.apiKey = savedConfig.zones[0].apiKey || config.apiKey;
            config.zoneId = savedConfig.zones[0].zoneId || config.zoneId;
        }
        config.tgEnabled = savedConfig.tgEnabled;
        config.scheduledEnabled = savedConfig.scheduledEnabled;
        if (savedConfig.targets.length > 0) {
            config.targets = savedConfig.targets;
        }
        applyZoneDefaultsFromTargets(config);
    }

    if (config.targets.length === 0) {
        config.targets = [{ mode: 'A', domain: '', port: '443', minActive: GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE, stack: 'v4/v6', exitFilter: 'any' }];
    }

    if (request) {
        const url = new URL(request.url);
        config.projectUrl = `${url.protocol}//${url.host}`;
    }

    applyZoneDefaultsFromTargets(config);
    return Object.freeze(config);
}

async function batchAddToTrash(env, entries) {
    if (!entries || entries.length === 0) return;
    const trashKey = 'pool_trash';
    let trashList = parsePoolList(await env.IP_DATA.get(trashKey));
    const trashIPSet = new Set(trashList.map(t => extractIPKey(t)));
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

    for (const { ipAddr, reason, poolKey } of entries) {
        if (!trashIPSet.has(ipAddr)) {
            const trashEntry = `${ipAddr} # ${reason} ${timestamp}${poolKey ? ' 来自 ' + poolKey : ''}`;
            trashList.push(trashEntry);
            trashIPSet.add(ipAddr);
        }
    }

    if (trashList.length > GLOBAL_SETTINGS.MAX_TRASH_SIZE) {
        trashList = trashList.slice(-GLOBAL_SETTINGS.MAX_TRASH_SIZE);
    }

    await env.IP_DATA.put(trashKey, trashList.join('\n'));
}

function parseIPLine(line) {
    line = line.trim();
    if (!line || line.startsWith('#')) return null;

    // 分离注释部分
    const { main: mainPart, comment } = splitComment(line);
    const fields = mainPart.split(',').map(item => item.trim());
    if (fields.length > 1) {
        const normalizedAddress = parseIPLine(fields[0]);
        if (!normalizedAddress) return null;
        const metaFields = fields.slice(1, 4).map(item => item || 'null');
        return [extractIPKey(normalizedAddress), ...metaFields].join(',') + comment;
    }

    const isValidIP = ip => ip.split('.').every(o => { const n = Number(o); return n >= 0 && n <= 255; });
    const isValidPort = p => { const n = Number(p); return n >= 1 && n <= 65535; };

    // IPv6 [addr]:PORT
    let match = mainPart.match(/^\[([0-9a-fA-F:]+)\]:(\d+)$/);
    if (match && isValidPort(match[2])) return `[${match[1]}]:${match[2]}${comment}`;

    // 纯IPv6（默认443端口）
    if (/^[0-9a-fA-F:]+$/.test(mainPart) && mainPart.includes(':')) {
        return `[${mainPart.replace(/^\[/, '').replace(/\]$/, '')}]:443${comment}`;
    }

    // IP:PORT 格式
    match = mainPart.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/);
    if (match && isValidIP(match[1]) && isValidPort(match[2])) return `${match[1]}:${match[2]}${comment}`;

    // IP：PORT 格式（中文冒号）
    match = mainPart.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})：(\d+)$/);
    if (match && isValidIP(match[1]) && isValidPort(match[2])) return `${match[1]}:${match[2]}${comment}`;

    // IP 空格/Tab PORT
    const parts = mainPart.split(/\s+/);
    if (parts.length === 2) {
        const ip = parts[0].trim();
        const port = parts[1].trim();
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && /^\d+$/.test(port) && isValidIP(ip) && isValidPort(port)) {
            return `${ip}:${port}${comment}`;
        }
    }

    // 纯IP（默认443端口）
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(mainPart) && isValidIP(mainPart)) {
        return `${mainPart}:443${comment}`;
    }

    // 复杂格式
    const complexMatch = mainPart.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\D+(\d+)/);
    if (complexMatch && isValidIP(complexMatch[1]) && isValidPort(complexMatch[2])) return `${complexMatch[1]}:${complexMatch[2]}${comment}`;

    return null;
}

async function cleanIPListAsync(text, resolveDomains = true, config = null) {
    if (!text) return '';
    const map = new Map();
    const lines = text.split('\n');

    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;

        // 分离注释
        const { main: mainPart, comment } = splitComment(line);

        // 检测域名格式
        const domainMatch = mainPart.match(/^([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}):?(\d+)?$/);
        if (domainMatch) {
            // 如果不解析域名或没有config，跳过域名格式的行
            if (!resolveDomains || !config) continue;

            const domain = domainMatch[1];
            const port = domainMatch[2] || '443';

            if (domain.length > 253) continue;

            try {
                const ips = await resolveDomain(domain, config);
                if (ips && ips.length > 0) {
                    ips.slice(0, GLOBAL_SETTINGS.MAX_IPS_PER_DOMAIN).forEach(ip => {
                        const key = formatAddr(ip, port);
                        const fullFormat = `${key}${comment}`;
                        map.set(key, fullFormat);
                    });
                }
                continue;
            } catch (e) {
                console.error(`❌ 域名解析失败 ${domain}:`, e);
                continue;
            }
        }

    // IP格式
    const parsed = parseIPLine(line);
    if (parsed) {
        const key = extractIPKey(parsed);
        map.set(key, parsed);
    }
    }

    return Array.from(map.values()).join('\n');
}

async function loadFromRemoteUrl(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
        const hostname = parsed.hostname.toLowerCase();
        if (hostname === 'localhost' ||
            hostname.startsWith('127.') ||
            hostname.startsWith('10.') ||
            hostname.startsWith('192.168.') ||
            /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
            hostname.startsWith('169.254.') ||   // 链路本地地址 (AWS/GCP 元数据服务等)
            hostname.startsWith('100.64.') ||    // 运营商级 NAT (RFC 6598)
            hostname === 'metadata.google.internal' ||
            hostname === '0.0.0.0' ||
            hostname === '::1' ||
            hostname === '[::1]' ||
            hostname.startsWith('fc00:') ||
            hostname.startsWith('fe80:') ||
            hostname.startsWith('[fc00:') ||
            hostname.startsWith('[fe80:')) return '';
    } catch { return ''; }

    try {
        const r = await fetch(url, {
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.REMOTE_LOAD_TIMEOUT)
        });
        if (r.ok) {
            const text = await r.text();
            return await cleanIPListAsync(text, false); // 不解析域名，只清洗IP格式
        }
    } catch (e) {
        console.error(`❌ 远程加载失败 ${url}:`, e);
    }
    return '';
}

async function dohQuery(domain, type, config) {
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.DOH_TIMEOUT)
        });
        const d = await r.json();
        return Array.isArray(d.Answer) ? d.Answer : [];
    } catch (e) {
        console.error(`❌ DNS ${type}记录解析失败:`, e);
        return [];
    }
}

async function resolveDomainRecords(domain, config) {
    const [aRecords, aaaaRecords] = await Promise.all([
        dohQuery(domain, 'A', config),
        dohQuery(domain, 'AAAA', config)
    ]);

    const records = [
        ...aRecords.filter(a => a.type === 1 && a.data).map(a => ({ type: 'A', ip: a.data })),
        ...aaaaRecords.filter(a => a.type === 28 && a.data).map(a => ({ type: 'AAAA', ip: a.data }))
    ];

    const seen = new Set();
    return records.filter(record => {
        const key = `${record.type}:${record.ip}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

async function resolveDomain(domain, config) {
    const records = await resolveDomainRecords(domain, config);
    return records.map(record => record.ip);
}

async function resolveTXTRecord(domain, config) {
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=TXT`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.DOH_TIMEOUT)
        });
        const d = await r.json();

        if (!d.Answer?.length) {
            return { raw: '', ips: [] };
        }

        // 去掉DNS返回的引号
        const rawData = d.Answer[0].data;
        const ips = parseTXTContent(rawData);
        const raw = rawData.replace(/^"|"$/g, '');

        return { raw, ips };
    } catch (e) {
        console.error('❌ DNS TXT记录解析失败:', e);
        return { raw: '', ips: [] };
    }
}

function normalizeTextValue(value) {
    if (value === undefined || value === null) return '';
    return String(value).trim();
}

function normalizeNumberValue(value, fallback = '-') {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    const match = String(value).match(/\d+(?:\.\d+)?/);
    return match ? Number(match[0]) : fallback;
}

function normalizeAsnValue(value) {
    const text = normalizeTextValue(value);
    if (!text) return '';
    return text.replace(/^AS/i, '');
}

function normalizeExitInfo(stack, exit, fallbackColo = '') {
    if (!exit || typeof exit !== 'object') return null;
    const asn = normalizeAsnValue(exit.asn ?? exit.as ?? exit.asNumber);
    return {
        stack,
        ip: normalizeTextValue(exit.ip ?? exit.address ?? exit.query),
        ipType: normalizeTextValue(exit.ipType ?? exit.type ?? stack),
        colo: normalizeTextValue(exit.colo) || fallbackColo,
        country: normalizeTextValue(exit.country ?? exit.countryCode),
        city: normalizeTextValue(exit.city),
        loc: normalizeTextValue(exit.loc ?? exit.location),
        asn,
        asOrganization: normalizeTextValue(exit.asOrganization ?? exit.asname ?? exit.org ?? exit.isp)
    };
}

function extractCheckExits(data) {
    const exits = [];
    if (Array.isArray(data?.exits)) {
        for (const item of data.exits) {
            const exit = normalizeExitInfo(item?.stack ?? item?.ipType ?? 'default', item, item?.colo ?? data?.colo);
            if (exit) exits.push(exit);
        }
    }

    const probes = data?.probe_results ?? data?.probeResults ?? data?.probes ?? {};
    if (probes && typeof probes === 'object') {
        for (const [stack, probe] of Object.entries(probes)) {
            const ok = probe?.ok === true || probe?.success === true || probe?.status === 'success';
            const exit = normalizeExitInfo(stack, probe?.exit ?? probe?.egress ?? probe?.result, data?.colo);
            if (ok && exit) exits.push(exit);
        }
    }

    const directExit = normalizeExitInfo('default', data?.exit ?? data?.egress, data?.colo);
    if (directExit && !exits.some(item => item.ip === directExit.ip && item.stack === directExit.stack)) {
        exits.push(directExit);
    }

    return exits;
}

function getPreferredExitInfo(exits) {
    return exits.find(item => item.stack === 'ipv4') ||
        exits.find(item => item.stack === 'ipv6') ||
        exits[0] ||
        null;
}

function inferCheckStack(data, exits) {
    const raw = normalizeTextValue(data?.inferred_stack ?? data?.ip_stack ?? data?.stack);
    if (raw) return normalizeStackFilter(raw);

    const supportsIpv4 = data?.supports_ipv4 === true || exits.some(item => ['ipv4', 'v4'].includes(normalizeTextValue(item.stack).toLowerCase()));
    const supportsIpv6 = data?.supports_ipv6 === true || exits.some(item => ['ipv6', 'v6'].includes(normalizeTextValue(item.stack).toLowerCase()));
    if (data?.dual_stack === true || (supportsIpv4 && supportsIpv6)) return 'v4/v6';
    if (supportsIpv4) return 'v4';
    if (supportsIpv6) return 'v6';
    return 'null';
}

function joinMetaValues(values) {
    const unique = Array.from(new Set(values.map(value => normalizeTextValue(value)).filter(Boolean)));
    return unique.length ? unique.join('/') : 'null';
}

function normalizeCheckResult(data, requestedAddr = '') {
    if (!data || typeof data !== 'object') {
        return { success: false, candidate: requestedAddr, proxyIP: '', portRemote: '', responseTime: '-', colo: 'N/A', exits: [], ipInfo: null, asn: 'null', country: 'null', stack: 'null' };
    }

    const exits = extractCheckExits(data);
    const preferredExit = getPreferredExitInfo(exits);
    const success = data.success === true ||
        data.ok === true ||
        data.status === 'success' ||
        exits.length > 0;
    const stack = inferCheckStack(data, exits);
    const asn = joinMetaValues(exits.map(item => item.asn));
    const country = joinMetaValues(exits.map(item => item.country));

    const ipInfo = preferredExit ? {
        country: preferredExit.country || '未知',
        countryCode: '',
        city: preferredExit.city || '',
        isp: preferredExit.asOrganization || '',
        asn: preferredExit.asn ? `AS${preferredExit.asn}` : '',
        asname: preferredExit.asOrganization || ''
    } : null;

    return {
        success,
        candidate: normalizeTextValue(data.candidate) || requestedAddr,
        proxyIP: normalizeTextValue(data.proxyIP ?? data.proxyIp ?? data.ip) || extractHostFromAddr(requestedAddr),
        portRemote: normalizeTextValue(data.portRemote ?? data.port ?? data.remotePort) || extractPortFromAddr(requestedAddr),
        responseTime: normalizeNumberValue(data.responseTime ?? data.latency ?? data.duration ?? data.elapsed ?? data.time),
        colo: normalizeTextValue(data.colo ?? preferredExit?.colo) || 'N/A',
        message: normalizeTextValue(data.message ?? data.error),
        exits,
        ipInfo,
        asn,
        country,
        stack,
        supportsIpv4: stack === 'v4' || stack === 'v4/v6',
        supportsIpv6: stack === 'v6' || stack === 'v4/v6',
        dualStack: stack === 'v4/v6'
    };
}

function exitFilterMatchesResult(result, exitFilter = 'any') {
    const filter = normalizeExitFilter(exitFilter);
    if (filter === 'any') return true;
    const stack = normalizeStackFilter(result?.stack);
    if (filter === 'v4') return stack === 'v4';
    if (filter === 'v6') return stack === 'v6';
    if (filter === 'dual') return stack === 'v4/v6';
    return true;
}

function targetMetaMatchesResult(result, target) {
    if (target.country) {
        const countries = String(result.country || '').toUpperCase().split(/[\/,\s]+/).filter(Boolean);
        if (!countries.includes(String(target.country).toUpperCase())) return false;
    }
    if (target.asn) {
        const asns = String(result.asn || '').replace(/AS/gi, '').split(/[\/,\s]+/).filter(Boolean);
        if (!asns.includes(String(target.asn).replace(/^AS/i, ''))) return false;
    }
    return true;
}

function targetMetaMatchesStoredEntry(entry, target) {
    const meta = parsePoolEntry(entry);
    return targetMetaMatchesResult({ country: meta?.country, asn: meta?.asn }, target);
}

function buildCheckApiUrl(apiUrl, addr) {
    const encoded = encodeURIComponent(addr);
    if (apiUrl.includes('{proxyip}')) return apiUrl.replaceAll('{proxyip}', encoded);
    return `${apiUrl}${encoded}`;
}

// 批量检测IP列表，可选查询归属地
async function batchCheckIPs(ipList, checkFn, config, useBackupApi = false) {
    if (!ipList || ipList.length === 0) return [];

    // 垃圾桶复检时使用备用接口（如有）独立验证
    const effectiveCheckFn = (useBackupApi && config.checkApiBackup)
        ? (addr) => {
            const normalized = normalizeCheckAddr(addr);
            return checkProxyIPOnce(normalized, config.checkApiBackup)
                .then(r => r ?? { success: false });
        }
        : checkFn;

    const checkSettled = await Promise.allSettled(ipList.map(addr => effectiveCheckFn(addr)));
    const checkResults = checkSettled.map((r, i) => r.status === 'fulfilled'
        ? normalizeCheckResult(r.value, ipList[i])
        : normalizeCheckResult({ success: false }, ipList[i]));

    return checkResults.map((result, i) => ({
        address: ipList[i],
        success: result.success,
        colo: result.colo || 'N/A',
        time: result.responseTime || '-',
        exits: result.exits || [],
        proxyIP: result.proxyIP || extractHostFromAddr(ipList[i]),
        portRemote: result.portRemote || extractPortFromAddr(ipList[i]),
        ipInfo: result.ipInfo || null,
        asn: result.asn || 'null',
        country: result.country || 'null',
        stack: result.stack || 'null'
    }));
}

async function getDomainStatus(target, config) {
    const cfConfig = getTargetCFConfig(config, target);
    const result = {
        mode: target.mode,
        domain: target.domain,
        port: target.port,
        aRecords: [],
        txtRecords: [],
        error: null
    };

    if (target.mode === 'A') {
        const [aRecords, aaaaRecords] = await Promise.all([
            fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=A`),
            fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=AAAA`)
        ]);
        if (aRecords === null || aaaaRecords === null) {
            result.error = CF_ERROR_MSG;
            return result;
        }
        const records = [...aRecords, ...aaaaRecords];
        // 使用批量检测流程
        const ipList = records.map(r => formatAddr(r.content, target.port));
        const checkResults = await batchCheckIPs(ipList, (addr) => checkProxyIP(addr, config), config);

        result.aRecords = records.map((r, i) => ({
            id: r.id,
            recordType: r.type,
            ip: r.content,
            port: target.port,
            address: formatAddr(r.content, target.port),
            success: checkResults[i].success,
            colo: checkResults[i].colo,
            time: checkResults[i].time,
            exits: checkResults[i].exits,
            proxyIP: checkResults[i].proxyIP,
            portRemote: checkResults[i].portRemote,
            asn: checkResults[i].asn,
            country: checkResults[i].country,
            stack: checkResults[i].stack,
            ipInfo: checkResults[i].ipInfo
        }));
    }

    if (target.mode === 'TXT') {
        const records = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=TXT`);
        if (!records) {
            result.error = CF_ERROR_MSG;
            return result;
        }
        if (records.length > 0) {
            const ips = parseTXTContent(records[0].content);

            // 使用批量检测流程
            const checkResults = await batchCheckIPs(ips, (addr) => checkProxyIP(addr, config), config);

            const txtChecks = checkResults.map(result => ({
                ip: result.address,
                address: result.address,
                success: result.success,
                colo: result.colo,
                time: result.time,
                exits: result.exits,
                proxyIP: result.proxyIP,
                portRemote: result.portRemote,
                asn: result.asn,
                country: result.country,
                stack: result.stack,
                ipInfo: result.ipInfo
            }));

            result.txtRecords = [{
                id: records[0].id,
                ips: txtChecks
            }];
        }
    }

    return result;
}

// 单次检测IP（不带重试）
async function checkProxyIPOnce(addr, apiUrl) {
    try {
        const url = buildCheckApiUrl(apiUrl, addr);

        const r = await fetch(url, { signal: AbortSignal.timeout(GLOBAL_SETTINGS.CHECK_TIMEOUT) });
        if (!r.ok) return null;

        const data = safeJSONParse(await r.text(), null);
        return data && typeof data === 'object' ? normalizeCheckResult(data, addr) : null;
    } catch {
        return null;
    }
}

// 地址格式化：智能添加默认端口443，处理IPv6方括号
function normalizeCheckAddr(input) {
    let addr = input.trim();
    if (addr.startsWith('[')) {
        if (!addr.includes(']:')) {
            addr = addr.endsWith(']') ? `${addr}:443` : `${addr}]:443`;
        }
    } else if (!addr.includes(':') || (addr.match(/:/g) || []).length > 1) {
        if ((addr.match(/:/g) || []).length > 1) {
            addr = `[${addr}]:443`;
        } else {
            addr = `${addr}:443`;
        }
    }
    return addr;
}

async function checkProxyIP(input, config) {
    const addr = normalizeCheckAddr(input);

    // 主接口检测
    const result = await checkProxyIPOnce(addr, config.checkApi);
    if (result !== null) return result;

    // 备用接口检测
    if (config.checkApiBackup) {
        const backup = await checkProxyIPOnce(addr, config.checkApiBackup);
        if (backup !== null) return backup;
    }

    return normalizeCheckResult({ success: false }, addr);
}

async function fetchCF(config, path, method = 'GET', body = null) {
    if (!config.apiKey || !config.zoneId) {
        console.error('❌ Cloudflare配置不完整:', {
            apiKey: !!config.apiKey,
            zoneId: !!config.zoneId
        });
        return null;
    }

    const headers = {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json'
    };
    const init = { method, headers };
    if (body) init.body = JSON.stringify(body);

    try {
        const r = await fetch(`https://api.cloudflare.com/client/v4${path}`, init);
        const d = await r.json();

        if (!d.success) {
            console.error('❌ Cloudflare API错误:', {
                path,
                method,
                errors: d.errors,
                messages: d.messages
            });
            return null;
        }

        return d.result;
    } catch (e) {
        console.error('❌ Cloudflare API请求失败:', {
            path,
            method,
            error: e.message
        });
        return null;
    }
}

function getTargetCFConfig(config, target) {
    const zone = Number.isInteger(target?.zoneIndex) && Array.isArray(config.zones)
        ? config.zones[target.zoneIndex]
        : null;
    return {
        ...config,
        apiKey: zone?.apiKey || config.apiKey,
        zoneId: zone?.zoneId || config.zoneId
    };
}

async function getCandidateIPs(env, target, addLog, poolKey) {
    const pool = await env.IP_DATA.get(poolKey) || '';
    
    if (!pool) {
        addLog(`⚠️ ${poolKey} 为空`);
        return [];
    }
    
    let candidates = parsePoolList(pool);
    
    // TXT模式不过滤端口，地址记录模式才过滤
    if (target.mode === 'A') {
        candidates = candidates.filter(l => {
            // 出口类型必须靠检测 API 实时判断；池内旧 stack 字段只保留兼容，不参与预筛。
            const ipPort = extractIPKey(l);
            return extractPortFromAddr(ipPort) === target.port && targetMetaMatchesStoredEntry(l, target);
        });
    } else {
        candidates = candidates.filter(l => targetMetaMatchesStoredEntry(l, target));
    }
    
    addLog(`📦 使用 ${poolKey}: ${candidates.length} 个候选IP`);
    return candidates;
}

async function maintainRecordsCommon(options) {
    const {
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs,
        deleteRecord,
        addRecord,
        shouldSkipCandidate
    } = options;

    const currentIPs = getCurrentIPs();
    let poolList = parsePoolList(await env.IP_DATA.get(poolKey));
    report.poolKeyUsed = poolKey;

    let validIPs = [];
    let poolModified = false;
    const trashBatch = [];

    // 并行检测所有现有IP
    const checkSettled = await Promise.allSettled(
        currentIPs.map(item => checkFn(item.addr).then(
            r => ({ item, result: normalizeCheckResult(r, item.addr) }),
            () => ({ item, result: normalizeCheckResult({ success: false }, item.addr) })
        ))
    );
    const checkResults = checkSettled.map(r =>
        r.status === 'fulfilled' ? r.value : { item: currentIPs[0], result: normalizeCheckResult({ success: false }, currentIPs[0]?.addr || '') }
    );
    // 串行处理结果（删除操作需要顺序执行）
    for (const { item, result: checkResult } of checkResults) {
        report.checkDetails.push({
            ip: item.addr,
            status: checkResult.success ? '✅ 活跃' : '❌ 失效',
            colo: checkResult.colo || 'N/A',
            time: checkResult.responseTime || '-',
            country: checkResult.country || 'null',
            asn: checkResult.asn || 'null'
        });

            if (checkResult.success && exitFilterMatchesResult(checkResult, target.exitFilter) && targetMetaMatchesResult(checkResult, target)) {
                validIPs.push(item.ip);
                addLog(`  ✅ ${item.addr} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
        } else if (checkResult.success) {
            report.removed.push({ ip: item.addr, reason: '出口/国家/ASN不匹配', colo: checkResult.colo || 'N/A', time: checkResult.responseTime || '-', country: checkResult.country || 'null', asn: checkResult.asn || 'null' });
            await deleteRecord(item.id);

            poolList = poolList.filter(p => extractIPKey(p) !== item.addr);
            report.poolRemoved++;
            poolModified = true;

            trashBatch.push({ ipAddr: item.addr, reason: '出口/国家/ASN不匹配', poolKey });
            addLog(`  ❌ ${item.addr} - 出口/国家/ASN不匹配，已删除`);
        } else {
            report.removed.push({ ip: item.addr, reason: '检测失效', colo: checkResult.colo || 'N/A', time: checkResult.responseTime || '-', country: checkResult.country || 'null', asn: checkResult.asn || 'null' });
            await deleteRecord(item.id);

            poolList = poolList.filter(p => extractIPKey(p) !== item.addr);
            report.poolRemoved++;
            poolModified = true;

            trashBatch.push({ ipAddr: item.addr, reason: '维护失效', poolKey });
            addLog(`  ❌ ${item.addr} - 失效已删除，已放入垃圾桶`);
        }
    }

    report.beforeActive = validIPs.length;

    // 补充IP
    if (validIPs.length < target.minActive) {
        addLog(`需补充: ${target.minActive - validIPs.length} 个`);
        const candidates = await getCandidateIPs(env, target, addLog, poolKey);

        for (const item of candidates) {
            if (validIPs.length >= target.minActive) break;
            const ipPort = extractIPKey(item);
            if (!ipPort || shouldSkipCandidate(ipPort, validIPs)) continue;

            const checkResult = await checkFn(ipPort);
            const normalizedCheck = normalizeCheckResult(checkResult, ipPort);
            if (normalizedCheck && normalizedCheck.success && (!exitFilterMatchesResult(normalizedCheck, target.exitFilter) || !targetMetaMatchesResult(normalizedCheck, target))) {
                addLog(`  ⏭️ ${ipPort} - 出口/国家/ASN不匹配`);
                continue;
            }
            if (normalizedCheck && normalizedCheck.success) {
                const ip = extractHostFromAddr(ipPort);
                await addRecord(ip);
                validIPs.push(ip);
                report.added.push({ ip: ipPort, colo: normalizedCheck.colo || 'N/A', time: normalizedCheck.responseTime || '-', country: normalizedCheck.country || 'null', asn: normalizedCheck.asn || 'null' });
                addLog(`  ✅ ${ipPort} - ${normalizedCheck.colo} (${normalizedCheck.responseTime}ms)`);
            } else {
                poolList = poolList.filter(p => extractIPKey(p) !== ipPort);
                report.poolRemoved++;
                poolModified = true;
                trashBatch.push({ ipAddr: ipPort, reason: '补充检测失败', poolKey });
                addLog(`  ❌ ${ipPort} - 检测失败，从池中移除并放入垃圾桶`);
            }
        }

        if (validIPs.length < target.minActive) {
            report.poolExhausted = true;
            addLog(`⚠️ ${poolKey} 库存不足，无法达到最小活跃数 ${target.minActive}`);
        }
    }

    // 批量写入垃圾桶
    if (trashBatch.length > 0) {
        await batchAddToTrash(env, trashBatch);
    }

    if (poolModified) {
        await env.IP_DATA.put(poolKey, poolList.join('\n'));
    }

    report.poolAfterCount = poolList.length;
    report.afterActive = validIPs.length;
}

async function maintainARecords(env, target, addLog, report, poolKey, checkFn, config) {
        const filters = [target.country ? `国家:${target.country}` : '', target.asn ? `ASN:${target.asn}` : ''].filter(Boolean).join(', ') || '无';
        addLog(`📋 维护地址记录(A/AAAA): ${target.domain}:${target.port} (最小活跃数: ${target.minActive}, 筛选: ${filters})`);
    const cfConfig = getTargetCFConfig(config, target);

    const [aRecords, aaaaRecords] = await Promise.all([
        fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=A`),
        fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=AAAA`)
    ]);

    if (aRecords === null || aaaaRecords === null) {
        addLog(`❌ 无法获取A/AAAA记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }

    const records = [...aRecords, ...aaaaRecords];
    addLog(`当前地址记录: A ${aRecords.length} 条 / AAAA ${aaaaRecords.length} 条`);

    // 使用通用维护逻辑
    await maintainRecordsCommon({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs: () => records.map(({ id, content, type }) => ({ id, type, addr: formatAddr(content, target.port), ip: content })),
        deleteRecord: async (id) => {
            const r = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`, 'DELETE');
            if (r === null) addLog(`  ⚠️ 删除地址记录失败: ${id}`);
        },
        addRecord: async (ip) => {
            const recordType = getDNSRecordTypeForIP(ip);
            const r = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records`, 'POST', {
                type: recordType,
                name: target.domain,
                content: ip.replace(/^\[/, '').replace(/\]$/, ''),
                ttl: 60,
                proxied: false
            });
            if (r === null) addLog(`  ⚠️ 添加${recordType}记录失败: ${ip}`);
        },
        shouldSkipCandidate: (ipPort, activeList) => {
            const ip = extractHostFromAddr(ipPort);
            const port = extractPortFromAddr(ipPort);
            return port !== target.port || activeList.includes(ip);
        }
    });
}

async function maintainTXTRecords(env, target, addLog, report, poolKey, checkFn, config) {
    const filters = [target.country ? `国家:${target.country}` : '', target.asn ? `ASN:${target.asn}` : ''].filter(Boolean).join(', ') || '无';
    addLog(`📝 维护TXT: ${target.domain} (最小活跃数: ${target.minActive}, 筛选: ${filters})`);
    const cfConfig = getTargetCFConfig(config, target);

    const records = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=TXT`);

    if (records === null) {
        addLog(`❌ 无法获取TXT记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }

    let currentIPs = [];
    let recordId = null;

    if (records?.length > 0) {
        recordId = records[0].id;
        currentIPs = parseTXTContent(records[0].content);
        addLog(`当前TXT: ${currentIPs.length} 个IP`);
    }

    // 记录原始内容用于后续比较
    const originalIPs = [...currentIPs];

    // 使用通用维护逻辑（TXT模式：deleteRecord/addRecord 为空操作，最后统一更新）
    await maintainRecordsCommon({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs: () => currentIPs.map(addr => ({ id: recordId, addr, ip: addr })),
        deleteRecord: async () => { /* TXT模式延迟到最后统一更新 */ },
        addRecord: async () => { /* TXT模式延迟到最后统一更新 */ },
        shouldSkipCandidate: (ipPort, activeList) => activeList.includes(ipPort)
    });

    // 从report中提取最终有效IP列表
    // 现有IP中有效的 = 原始IP - 被移除的IP
    const removedSet = new Set(report.removed.map(r => r.ip));
    const survivedIPs = originalIPs.filter(ip => !removedSet.has(ip));
    // 新增的IP
    const addedIPs = report.added.map(a => a.ip);
    // 最终有效IP列表
    const finalValidIPs = [...survivedIPs, ...addedIPs];

    // TXT记录特殊处理：统一更新
    const newContent = finalValidIPs.length > 0 ? `"${finalValidIPs.join(',')}"` : '';
    const currentContent = originalIPs.length > 0 ? `"${originalIPs.join(',')}"` : '';

    if (newContent !== currentContent) {
        if (newContent === '' && recordId) {
            const r = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${recordId}`, 'DELETE');
            addLog(r !== null ? `📝 TXT记录已删除（所有IP失效）` : `⚠️ TXT记录删除失败`);
        } else if (newContent !== '') {
            if (recordId) {
                const r = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${recordId}`, 'PUT', {
                    type: 'TXT', name: target.domain, content: newContent, ttl: 60
                });
                addLog(r !== null ? `📝 TXT已更新` : `⚠️ TXT更新失败`);
            } else {
                const r = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records`, 'POST', {
                    type: 'TXT', name: target.domain, content: newContent, ttl: 60
                });
                addLog(r !== null ? `📝 TXT已创建` : `⚠️ TXT创建失败`);
            }
        }
        report.txtUpdated = true;
    }
}

async function maintainAllDomains(env, isManual = false, config) {
    const allReports = [];
    const startTime = Date.now();

    const poolStats = new Map();
    // 内联 loadDomainPoolMapping
    const mappingJson = await env.IP_DATA.get('domain_pool_mapping') || '{}';
    const domainPoolMapping = safeJSONParse(mappingJson, {});

    // 单次维护任务内缓存 proxyip 检测结果，减少重复外部请求（不改变结果，仅减少请求次数）
    const checkCache = new Map();
    const checkProxyIPCached = async (addr) => {
        const key = (addr || '').trim();
        if (!key) return normalizeCheckResult({ success: false }, key);
        if (checkCache.has(key)) {
            const cached = checkCache.get(key);
            return cached && typeof cached.then === 'function' ? await cached : cached;
        }
        const p = checkProxyIP(key, config);
        checkCache.set(key, p);
        const res = await p;
        checkCache.set(key, res);
        return res;
    };

    const allKeys = await env.IP_DATA.list();
    const poolSettled = await Promise.allSettled(
        allKeys.keys.filter(k => k.name.startsWith('pool')).map(async k => {
            const raw = await env.IP_DATA.get(k.name) || '';
            return [k.name, parsePoolList(raw).length];
        })
    );
    const poolEntries = poolSettled
        .map(r => r.status === 'fulfilled' ? r.value : null)
        .filter(e => e !== null);
    poolEntries.forEach(([name, count]) => poolStats.set(name, { before: count, after: count }));

    for (let i = 0; i < config.targets.length; i++) {
        const target = config.targets[i];
        if (target.enabled === false) {
            console.log(formatLogMessage(`⏸️ 跳过维护: ${target.domain} 已关闭`));
            continue;
        }
        const { domain, mode, port, minActive } = target;

        const report = {
            target,
            domain,
            mode,
            port,
            minActive,
            beforeActive: 0,
            afterActive: 0,
            added: [],
            removed: [],
            poolRemoved: 0,
            poolExhausted: false,
            configError: false,
            checkDetails: [],
            logs: []
        };
        
        const addLog = (m) => {
            const formattedMsg = formatLogMessage(m);
            report.logs.push(formattedMsg);
            console.log(formattedMsg);
        };
        
        addLog(`🚀 开始维护: ${target.domain}`);
        // 内联 getPoolKeyForDomain
        const poolKey = domainPoolMapping?.[target.domain] ?? 'pool';

        if (target.mode === 'A') {
            await maintainARecords(env, target, addLog, report, poolKey, checkProxyIPCached, config);
        } else if (target.mode === 'TXT') {
            await maintainTXTRecords(env, target, addLog, report, poolKey, checkProxyIPCached, config);
        }
        
        addLog(`✅ 完成: ${report.afterActive}/${target.minActive}`);
        allReports.push(report);
    }

    // 更新池统计（无需再次遍历 KV 读取：直接使用维护过程中已知的最终池长度）
    for (const r of allReports) {
        if (r && r.poolKeyUsed && typeof r.poolAfterCount === 'number' && poolStats.has(r.poolKeyUsed)) {
            poolStats.get(r.poolKeyUsed).after = r.poolAfterCount;
        }
    }

    // 重新读取垃圾桶的实际数量（维护过程中 batchAddToTrash 直接写入 KV，不经过 report）
    if (poolStats.has('pool_trash')) {
        const trashRaw = await env.IP_DATA.get('pool_trash') || '';
        poolStats.get('pool_trash').after = parsePoolList(trashRaw).length;
    }
     
    // 1. 检查是否有IP变化（删除或新增）
    const hasIPChanges = allReports.some(r => 
        r.added.length > 0 || 
        r.removed.length > 0 || 
        (r.txtAdded && r.txtAdded.length > 0) || 
        (r.txtRemoved && r.txtRemoved.length > 0)
    );
    
    // 2. 检查是否有配置错误
    const hasConfigError = allReports.some(r => r.configError);

    // 3. 检查是否有域名活跃数不足且无法补充IP
    // 注：poolExhausted 表示候选IP不足（包括池枯竭、端口不匹配等情况）
    const hasInsufficientActive = allReports.some(r => 
        r.afterActive < r.minActive && r.poolExhausted
    );
    
    // 通知条件：手动执行 OR IP变化 OR 活跃数不足 OR 配置错误
    // 注：移除了 hasPoolExhausted，因为 hasInsufficientActive 已涵盖"无法补充IP"的场景
    const shouldNotify = isManual || hasIPChanges || hasInsufficientActive || hasConfigError;

    let tgResult = { sent: false, reason: 'no_need' };
    if (shouldNotify && config.tgEnabled !== false) {
        tgResult = await sendTG(allReports, poolStats, isManual, config);
    } else if (shouldNotify) {
        tgResult = { sent: false, reason: 'disabled', message: 'TG通知已关闭' };
    }

    console.log(`✅ 维护任务完成，总耗时: ${Date.now() - startTime}ms，处理域名: ${config.targets.length}个`);
    
    return {
        success: true,
        reports: allReports,
        poolStats: Object.fromEntries(poolStats),
        notified: tgResult.sent,
        tgStatus: tgResult,
        processingTime: Date.now() - startTime
    };
}

function formatReportMeta(item = {}) {
    const parts = [];
    if (item.colo && item.colo !== 'N/A') parts.push(item.colo);
    if (item.time && item.time !== '-') parts.push(`${item.time}ms`);
    const countries = String(item.country || '').split(/[\/,\s]+/).filter(v => v && v !== 'null');
    const asns = String(item.asn || '').split(/[\/,\s]+/).filter(v => v && v !== 'null').map(v => v.toUpperCase().startsWith('AS') ? v.toUpperCase() : 'AS' + v);
    if (countries.length) parts.push([...new Set(countries)].join('/'));
    if (asns.length) parts.push([...new Set(asns)].join('/'));
    return parts.length ? parts.join(' · ') : '无详情';
}

function formatIPChanges(added, removed, port = '', minActive = 0, afterActive = 0) {
    let msg = '';
    if (added && added.length > 0) {
        msg += `📈 新增 ${added.length} 个IP\n`;
        added.forEach(item => {
            const displayIP = extractPortFromAddr(item.ip, '') ? item.ip : formatAddr(item.ip, port);
            msg += `   ✅ <code>${displayIP}</code>\n`;
            msg += `      ${formatReportMeta(item)}\n`;
        });
    }
    if (removed && removed.length > 0) {
        msg += `📉 移除 ${removed.length} 个IP\n`;
        removed.forEach(item => {
            msg += `   ❌ <code>${item.ip}</code>\n`;
            msg += `      ${formatReportMeta(item)}\n`;
            msg += `      原因: ${item.reason}\n`;
        });
    }
    if ((!added || added.length === 0) && (!removed || removed.length === 0)) {
        msg += `✨ 所有IP正常，无变化\n`;
    }
    msg += `✅ 完成: ${afterActive}/${minActive}\n`;
    return msg;
}

async function sendTG(reports, poolStats, isManual, config) {
    if (!config.tgToken || !config.tgId) {
        console.log('📱 TG未配置，跳过通知');
        return { sent: false, reason: 'not_configured', message: 'TG未配置' };
    }

    const modeLabel = { 'A': 'A/AAAA', 'TXT': 'TXT' };
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

    let msg = isManual ? `🔧 <b>DDNS 手动维护报告</b>\n` : `⚙️ <b>DDNS 自动维护报告</b>\n`;
    msg += `━━━━━━━━━━━━━━━━━━\n⏰ ${timestamp}\n\n`;

    const hasConfigError = reports.some(r => r.configError);
    if (hasConfigError) {
        msg += `⚠️ <b>警告: 检测到配置错误</b>\n请检查 CF_KEY, CF_ZONEID 是否正确配置\n\n`;
    }

    reports.forEach((report, index) => {
        if (index > 0) msg += `\n`;
        msg += `━━ <code>${report.domain}</code> ━━\n`;
        msg += `${modeLabel[report.mode]}`;
        if (report.mode === 'A') msg += ` · 端口 ${report.port}`;
        msg += ` · 最小活跃数 ${report.minActive}\n\n`;

        if (report.configError) {
            msg += `❌ <b>配置错误，无法获取记录</b>\n`;
            return;
        }

        // 检测详情
        if (report.checkDetails && report.checkDetails.length > 0) {
            report.checkDetails.forEach(d => {
                const icon = d.status.includes('✅') ? '✅' : '❌';
                msg += `${icon} <code>${d.ip}</code>\n   ${formatReportMeta(d)}\n`;
            });
            msg += `\n`;
        }

        if (report.mode === 'A') {
            msg += formatIPChanges(report.added, report.removed, report.port, report.minActive, report.afterActive);
        }

        if (report.mode === 'TXT') {
            msg += formatIPChanges(report.added, report.removed, '', report.minActive, report.afterActive);
        }
    });

    msg += `\n━━━━━━━━━━━━━━━━━━\n`;
    msg += `📦 <b>IP池库存统计</b>\n`;

    for (const [poolKey, stats] of poolStats) {
        const displayName = getPoolDisplayName(poolKey);
        msg += `\n<b>${displayName}</b>\n`;
        msg += `   维护前: ${stats.before} 个\n`;
        msg += `   维护后: ${stats.after} 个\n`;

        const change = stats.after - stats.before;
        if (change !== 0) {
            const changeSymbol = change > 0 ? '📈' : '📉';
            msg += `   ${changeSymbol} 变化: ${change > 0 ? '+' : ''}${change}\n`;
        }

        // 垃圾桶/系统数据池不参与枯竭或低库存告警
        if (poolKey !== 'pool_trash' && poolKey !== 'domain_pool_mapping') {
            if (stats.after === 0 && stats.before > 0) {
                msg += `   ⚠️ <b>警告：${displayName}已枯竭！</b>\n`;
            } else if (stats.after < 10) {
                msg += `   ⚠️ 库存较低\n`;
            }
        }
    }

    if (isManual && config.projectUrl) {
        msg += `\n🔗 <a href="${config.projectUrl}">打开管理面板</a>\n`;
    }

    try {
        const response = await fetch(`https://api.telegram.org/bot${config.tgToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: config.tgId,
                text: msg,
                parse_mode: 'HTML',
                disable_web_page_preview: true
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('❌ TG配置错误，发送失败。请检查TG_TOKEN和TG_ID是否正确:', errorData);
            return {
                sent: false,
                reason: 'config_error',
                message: 'TG配置错误，请检查TG_TOKEN和TG_ID',
                detail: errorData.description || '未知错误'
            };
        } else {
            console.log('✅ TG通知发送成功');
            return { sent: true, reason: 'success', message: 'TG通知发送成功' };
        }
    } catch (e) {
        console.error('❌ TG发送失败，网络错误:', e.message);
        return {
            sent: false,
            reason: 'network_error',
            message: 'TG发送失败，网络错误',
            detail: e.message
        };
    }
}

function renderHTML(C, runtimeState = {}) {
    const targetsJson = JSON.stringify(C.targets);
    const settingsJson = JSON.stringify(GLOBAL_SETTINGS);
    const appConfigJson = JSON.stringify(getEditableConfig(C));
    const kvReady = runtimeState.kvReady !== false;
    const version = APP_VERSION;
    
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro - IP管理面板</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🌐</text></svg>">
    <style>
        :root {
            --primary: #007aff;
            --success: #34c759;
            --warning: #ff9500;
            --danger: #ff3b30;
            --bg: #f5f5f7;
            --card: #fff;
            --text: #1d1d1f;
            --secondary: #86868b;
        }
        *, *::before, *::after { box-sizing: border-box; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        button, input, select, textarea { font-family: inherit; font-size: inherit; line-height: inherit; margin: 0; }
        table { border-collapse: collapse; }
        /* ── Bootstrap replacement: Grid ── */
        .container { width: 100%; max-width: 1140px; margin: 0 auto; padding: 0 12px; }
        .row { display: flex; flex-wrap: wrap; margin: 0 -6px; }
        .row > * { padding: 0 6px; }
        .row.g-2 { margin: 0 -4px; }
        .row.g-2 > * { padding: 4px; }
        .col-6 { flex: 0 0 50%; max-width: 50%; }
        .col-lg-5, .col-lg-7 { flex: 0 0 100%; max-width: 100%; }
        @media (min-width: 992px) {
            .col-lg-5, .col-lg-7 { flex: 0 0 50%; max-width: 50%; }
        }
        /* ── Bootstrap replacement: Forms ── */
        .form-control, .form-select { display: block; width: 100%; font-size: 1rem; line-height: 1.5; color: #212529; background-clip: padding-box; appearance: none; }
        .form-control-sm { font-size: .875rem; padding: .25rem .5rem; }
        .form-select { background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill='none' stroke='%23343a40' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='m2 5 6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right .75rem center; background-size: 16px 12px; padding-right: 2.25rem; }
        .form-select-sm { font-size: .875rem; padding: .25rem 2rem .25rem .5rem; }
        .input-group { display: flex; flex-wrap: wrap; align-items: stretch; width: 100%; }
        .input-group > .form-control { flex: 1 1 auto; width: 1%; min-width: 0; position: relative; }
        .input-group > .btn { position: relative; z-index: 2; }
        .input-group > :not(:first-child) { border-top-left-radius: 0 !important; border-bottom-left-radius: 0 !important; }
        .input-group > :not(:last-child) { border-top-right-radius: 0 !important; border-bottom-right-radius: 0 !important; }
        .input-group-sm > .form-control, .input-group-sm > .btn { font-size: .875rem; padding: .25rem .5rem; }
        textarea.form-control { min-height: calc(1.5em + .75rem + 2px); }
        /* ── Bootstrap replacement: Buttons ── */
        .btn { display: inline-block; text-align: center; vertical-align: middle; cursor: pointer; user-select: none; line-height: 1.5; font-size: 1rem; background: transparent; border: 1px solid transparent; color: inherit; text-decoration: none; }
        .btn-sm { font-size: .875rem; padding: .25rem .5rem; border-radius: .25rem; }
        .btn-primary { background: var(--primary); color: #fff; border: 1px solid var(--primary); }
        .btn-success { background: var(--success); color: #fff; border: 1px solid var(--success); }
        .btn-danger { background: var(--danger); color: #fff; border: 1px solid var(--danger); }
        .btn-info { background: #0dcaf0; color: #000; border: 1px solid #0dcaf0; }
        .btn-dark { background: #212529; color: #fff; border: 1px solid #212529; }
        .btn-outline-primary { background: transparent; color: var(--primary); border: 1px solid var(--primary); }
        .btn-outline-primary:hover { background: var(--primary); color: #fff; }
        .btn-outline-secondary { background: transparent; color: #6c757d; border: 1px solid #6c757d; }
        .btn-outline-secondary:hover { background: #6c757d; color: #fff; }
        .btn-outline-success { background: transparent; color: var(--success); border: 1px solid var(--success); }
        .btn-outline-success:hover { background: var(--success); color: #fff; }
        .btn-outline-danger { background: transparent; color: var(--danger); border: 1px solid var(--danger); }
        .btn-outline-danger:hover { background: var(--danger); color: #fff; }
        /* ── Bootstrap replacement: Tables ── */
        .table { width: 100%; margin-bottom: 1rem; vertical-align: top; border-color: #dee2e6; }
        .table > :not(caption) > * > * { padding: .5rem; }
        .table-sm > :not(caption) > * > * { padding: .25rem; }
        .table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        /* ── Bootstrap replacement: Badge / Progress ── */
        .badge { display: inline-block; padding: .35em .65em; font-size: .75em; font-weight: 700; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: .375rem; }
        .progress { display: flex; height: 1rem; overflow: hidden; font-size: .75rem; background-color: #e9ecef; border-radius: .375rem; }
        .progress-bar { display: flex; flex-direction: column; justify-content: center; overflow: hidden; color: #fff; text-align: center; white-space: nowrap; transition: width .6s ease; }
        /* ── Bootstrap replacement: Utilities - Spacing ── */
        .m-0 { margin: 0 !important; }
        .mb-0 { margin-bottom: 0 !important; }
        .mb-1 { margin-bottom: .25rem !important; }
        .mb-2 { margin-bottom: .5rem !important; }
        .mb-3 { margin-bottom: 1rem !important; }
        .mt-2 { margin-top: .5rem !important; }
        .mt-auto { margin-top: auto !important; }
        .p-3 { padding: 1rem !important; }
        .p-4 { padding: 1.5rem !important; }
        .pb-5 { padding-bottom: 3rem !important; }
        /* ── Bootstrap replacement: Utilities - Flex ── */
        .d-flex { display: flex !important; }
        .flex-wrap { flex-wrap: wrap !important; }
        .flex-grow-1 { flex-grow: 1 !important; }
        .flex-shrink-0 { flex-shrink: 0 !important; }
        .gap-1 { gap: .25rem !important; }
        .gap-2 { gap: .5rem !important; }
        .align-items-center { align-items: center !important; }
        .justify-content-between { justify-content: space-between !important; }
        /* ── Bootstrap replacement: Utilities - Text ── */
        .text-white { color: #fff !important; }
        .text-center { text-align: center !important; }
        .text-secondary { color: var(--secondary) !important; }
        .text-danger { color: var(--danger) !important; }
        .text-dark { color: #212529 !important; }
        .text-decoration-none { text-decoration: none !important; }
        .fw-bold { font-weight: 700 !important; }
        .small, small { font-size: .875em; }
        /* ── Bootstrap replacement: Utilities - Background ── */
        .bg-light { background-color: #f8f9fa !important; }
        .bg-success { background-color: var(--success) !important; }
        .bg-danger { background-color: var(--danger) !important; }
        /* ── Bootstrap replacement: Utilities - Size ── */
        .w-100 { width: 100% !important; }
        h6 { margin-top: 0; margin-bottom: .5rem; font-size: 1rem; font-weight: 500; }
        .hero {
            padding: 40px 0 20px;
            position: relative;
        }
        .hero h1 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--secondary);
            margin-bottom: 12px;
        }
        .hero-actions {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 8px;
            flex-wrap: wrap;
        }
        .guide-toggle {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 26px;
            height: 26px;
            border-radius: 999px;
            border: 1px solid #d0d3da;
            background: #ffffff;
            color: #6b7280;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .guide-toggle:hover {
            background: #f3f4f6;
            color: #111827;
            box-shadow: 0 2px 6px rgba(0,0,0,0.06);
        }
        .usage-guide {
            background: #ffffff;
            border-radius: 12px;
            padding: 10px 14px;
            margin-top: 10px;
            border: 1px solid #e5e7eb;
            font-size: 12px;
            color: #4b5563;
        }
        .usage-guide ol {
            padding-left: 18px;
            margin: 0;
        }
        .usage-guide li {
            margin-bottom: 4px;
        }
        .github-corner {
            position: fixed;
            top: 0;
            right: 0;
            z-index: 9999;
        }
        .github-corner svg {
            fill: #86868b;
            color: #fff;
            width: 60px;
            height: 60px;
            transition: fill 0.3s;
        }
        .github-corner:hover svg {
            fill: #667eea;
        }
        .github-corner .octo-arm {
            transform-origin: 130px 106px;
        }
        .github-corner:hover .octo-arm {
            animation: octocat-wave 560ms ease-in-out;
        }
        @keyframes octocat-wave {
            0%, 100% { transform: rotate(0); }
            20%, 60% { transform: rotate(-25deg); }
            40%, 80% { transform: rotate(10deg); }
        }
        @media (max-width: 768px) {
            .github-corner svg {
                width: 50px;
                height: 50px;
            }
            .hero h1 {
                font-size: 1.2rem;
            }
        }
        .domain-selector {
            max-width: 600px;
        }
        .domain-selector select {
            border-radius: 12px;
            padding: 12px 16px;
            font-size: 1.1rem;
            font-weight: 600;
            border: 2px solid #e5e5e7;
        }
        @media (max-width: 768px) {
            .domain-selector select {
                font-size: 0.95rem;
                padding: 10px 12px;
            }
        }
        .card {
            border: none;
            border-radius: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.04);
            background: var(--card);
            margin-bottom: 24px;
        }
        .console {
            background: #1c1c1e;
            color: #32d74b;
            height: 380px;
            overflow-y: auto;
            font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
            padding: 20px;
            border-radius: 16px;
            font-size: 13px;
            line-height: 1.6;
        }
        .console::-webkit-scrollbar {
            width: 8px;
        }
        .console::-webkit-scrollbar-thumb {
            background: #3a3a3c;
            border-radius: 4px;
        }
        @media (max-width: 768px) {
            .console {
                height: 250px;
                font-size: 11px;
                padding: 12px;
            }
        }
        .table th {
            border: none;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--secondary);
            padding: 15px;
        }
        .table td {
            border-top: 1px solid #f2f2f2;
            padding: 15px;
            vertical-align: middle;
        }
        @media (max-width: 768px) {
            .table th, .table td {
                padding: 8px 4px;
                font-size: 11px;
            }
            .table {
                font-size: 12px;
            }
        }
        .btn {
            border-radius: 12px;
            font-weight: 600;
            padding: 10px 20px;
            transition: all 0.2s;
            border: none;
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        @media (max-width: 768px) {
            .btn {
                padding: 8px 12px;
                font-size: 13px;
            }
            .btn-sm {
                padding: 6px 10px;
                font-size: 12px;
            }
        }
        .form-control, .form-select {
            border-radius: 12px;
            background: #f5f5f7;
            border: 1px solid transparent;
            padding: 12px 16px;
        }
        .form-control:focus, .form-select:focus {
            background: #fff;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px rgba(0,122,255,0.1);
        }
        /* 固定高度滚动区域 */
        .scroll-box {
            max-height: 200px;
            overflow-y: auto;
            border-radius: 12px;
        }
        .scroll-box::-webkit-scrollbar {
            width: 6px;
        }
        .scroll-box::-webkit-scrollbar-thumb {
            background: #d1d1d6;
            border-radius: 3px;
        }
        .config-info {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--secondary);
            background: #f5f5f7;
            padding: 4px 10px;
            border-radius: 8px;
        }
        .kv-alert {
            margin-top: 12px;
            padding: 12px 14px;
            border: 1px solid #fecaca;
            background: #fff1f2;
            color: #991b1b;
            border-radius: 10px;
            font-size: 13px;
            line-height: 1.5;
        }
        .config-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
        }
        .config-grid .span-2 {
            grid-column: 1 / -1;
        }
        .field {
            display: flex;
            flex-direction: column;
            gap: 5px;
            min-width: 0;
        }
        .field > span {
            font-size: 13px;
            font-weight: 700;
            color: #1d1d1f;
        }
        .field > small {
            color: #6b7280;
            font-size: 11px;
            line-height: 1.35;
        }
        .config-card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 12px;
        }
        .config-mini-card {
            border: 1px solid #e5e7eb;
            background: #fbfbfd;
            border-radius: 10px;
            padding: 14px;
            min-height: 120px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            cursor: pointer;
            transition: border-color .2s ease, box-shadow .2s ease, transform .2s ease;
        }
        .config-mini-card:hover {
            border-color: rgba(0,122,255,.35);
            box-shadow: 0 8px 24px rgba(0,0,0,.06);
            transform: translateY(-1px);
        }
        .config-mini-card h5 {
            margin: 0;
            font-size: 17px;
            line-height: 1.25;
            word-break: break-all;
        }
        .config-mini-card .meta {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            color: #6b7280;
            font-size: 12px;
        }
        .config-mini-card .actions {
            display: flex;
            gap: 8px;
            margin-top: auto;
        }
        .config-mini-card .actions .btn {
            padding: 6px 10px;
            font-size: 12px;
        }
        .config-save-btn {
            position: sticky;
            top: 10px;
            z-index: 5;
        }
        .config-edit-panel {
            display: none;
            margin-top: 12px;
            padding: 14px;
            border: 1px solid #dbe3f0;
            border-radius: 10px;
            background: #fff;
        }
        .config-edit-panel.active {
            display: block;
        }
        .config-edit-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
        }
        .config-edit-actions {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            margin-top: 12px;
        }
        .filter-line {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 34px auto auto auto;
            gap: 6px;
            align-items: center;
        }
        .filter-help-btn {
            width: 34px;
            height: 34px;
            border-radius: 999px;
            border: 1px solid #d8dce3;
            background: #fff;
            color: #4b5563;
            font-weight: 800;
            cursor: pointer;
        }
        .filter-help {
            display: none;
            margin-top: 8px;
            padding: 10px 12px;
            border-radius: 10px;
            background: #f5f5f7;
            color: #4b5563;
            font-size: 12px;
            line-height: 1.55;
        }
        .filter-help.active {
            display: block;
        }
        .filter-preview {
            color: #6b7280;
            font-size: 12px;
            margin-top: 6px;
            min-height: 18px;
        }
        .filter-preview strong {
            color: #1d1d1f;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 56px;
            border-radius: 999px;
            padding: 5px 9px;
            font-size: 12px;
            font-weight: 700;
        }
        .status-badge.ok {
            color: #166534;
            background: #dcfce7;
        }
        .status-badge.bad {
            color: #991b1b;
            background: #fee2e2;
        }
        .latency-badge {
            display: inline-flex;
            min-width: 64px;
            justify-content: center;
            border-radius: 999px;
            padding: 5px 9px;
            font-size: 12px;
            font-weight: 700;
            color: #1d4ed8;
            background: #dbeafe;
        }
        .colo-badge {
            display: inline-flex;
            min-width: 48px;
            justify-content: center;
            border-radius: 999px;
            padding: 5px 9px;
            font-size: 12px;
            font-weight: 700;
            color: #374151;
            background: #f3f4f6;
        }
        .switch-row {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
        }
        .switch-row label {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            color: #4b5563;
        }
        .top-nav {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .nav-tab {
            border: 1px solid #d8dce3;
            background: #fff;
            color: #4b5563;
            border-radius: 999px;
            padding: 8px 14px;
            font-weight: 700;
            cursor: pointer;
        }
        .nav-tab.active {
            background: var(--primary);
            color: #fff;
            border-color: var(--primary);
        }
        .page-panel { display: none; }
        .page-panel.active { display: block; }
        .toast {
            position: fixed;
            right: 18px;
            bottom: 18px;
            z-index: 10001;
            background: #1f2937;
            color: #fff;
            padding: 10px 14px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,.18);
            opacity: 0;
            transform: translateY(8px);
            transition: opacity .2s ease, transform .2s ease;
            pointer-events: none;
        }
        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }
        .toast.success { background: #166534; }
        .toast.error { background: #991b1b; }
        .switch {
            position: relative;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            user-select: none;
            font-weight: 700;
            color: #374151;
        }
        .switch input {
            position: absolute;
            opacity: 0;
            pointer-events: none;
        }
        .switch-slider {
            width: 48px;
            height: 26px;
            border-radius: 999px;
            background: #cfd5df;
            position: relative;
            transition: background .2s ease;
        }
        .switch-slider::before {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            left: 3px;
            top: 3px;
            border-radius: 999px;
            background: #fff;
            box-shadow: 0 1px 4px rgba(0,0,0,.2);
            transition: transform .2s ease;
        }
        .switch input:checked + .switch-slider {
            background: var(--success);
        }
        .switch input:checked + .switch-slider::before {
            transform: translateX(22px);
        }
        @media (max-width: 768px) {
            .config-info {
                font-size: 9px;
                padding: 3px 6px;
            }
            .config-grid {
                grid-template-columns: 1fr;
            }
            .config-grid .span-2 {
                grid-column: auto;
            }
            .config-edit-grid {
                grid-template-columns: 1fr;
            }
        }
        .ip-info-tag {
            display: inline-block;
            background: #e8f4ff;
            color: var(--primary);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            margin-left: 4px;
        }
        .exit-list-cell {
            min-width: 430px;
            text-align: left;
            max-width: 760px;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        .exit-detail {
            display: grid;
            grid-template-columns: 48px minmax(260px, max-content) minmax(90px, .7fr) minmax(120px, 1fr);
            gap: 6px;
            align-items: center;
            margin: 2px 0;
            padding: 4px 0;
            border-bottom: 1px solid rgba(0,0,0,.05);
            min-height: 30px;
            width: max-content;
            min-width: 100%;
        }
        .exit-detail:last-child {
            border-bottom: 0;
        }
        .exit-ip {
            font-family: 'SF Mono', Consolas, monospace;
            font-weight: 700;
            color: #1d1d1f;
            white-space: nowrap;
            overflow: visible;
            text-overflow: clip;
            font-size: 11px;
            line-height: 1.25;
            cursor: pointer;
        }
        .copyable {
            cursor: pointer;
        }
        .copyable:hover {
            color: var(--primary);
            text-decoration: underline;
        }
        .exit-stack {
            background: #eef2ff;
            color: #4338ca;
        }
        .exit-field {
            min-width: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        @media (max-width: 768px) {
            .ip-info-tag {
                font-size: 9px;
                padding: 2px 4px;
                margin-left: 2px;
            }
        }

        /* 自定义模态对话框 */
        .custom-modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            backdrop-filter: blur(4px);
        }
        .custom-modal {
            background: #fff;
            border-radius: 16px;
            padding: 24px;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            animation: modalIn 0.2s ease-out;
        }
        @keyframes modalIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
        .custom-modal-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #1d1d1f;
        }
        .custom-modal-content {
            font-size: 14px;
            color: #4b5563;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        .custom-modal-stats {
            background: #f5f5f7;
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 16px;
        }
        .custom-modal-stats div {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
        }
        .custom-modal-stats .label {
            color: #86868b;
        }
        .custom-modal-stats .value {
            font-weight: 600;
            color: #1d1d1f;
        }
        .custom-modal-buttons {
            display: flex;
            gap: 12px;
        }
        .custom-modal-buttons button {
            flex: 1;
            padding: 12px 20px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }
        .custom-modal-buttons .btn-continue {
            background: var(--primary);
            color: #fff;
        }
        .custom-modal-buttons .btn-continue:hover {
            background: #0056b3;
        }
        .custom-modal-buttons .btn-abandon {
            background: #f5f5f7;
            color: #1d1d1f;
        }
        .custom-modal-buttons .btn-abandon:hover {
            background: #e5e5e7;
        }
        
        @media (max-width: 768px) {
            .exit-list-cell {
                min-width: 360px;
            }
            .exit-detail {
                grid-template-columns: 44px minmax(240px, max-content) minmax(90px, .7fr) minmax(110px, 1fr);
            }
            .badge {
                font-size: 10px;
                padding: 3px 6px;
            }
        }
        
        /* IP库管理和系统控制台卡片等高 */
        .col-lg-7 > .card.p-4:first-child,
        .col-lg-5 > .card.p-4 {
            display: flex;
            flex-direction: column;
        }
        @media (min-width: 992px) {
            .col-lg-7 > .card.p-4:first-child,
            .col-lg-5 > .card.p-4 {
                min-height: 580px;
            }
        }
        /* IP库管理卡片内部布局 - 让内容区域自动扩展，按钮固定底部 */
        .col-lg-7 > .card.p-4:first-child .ip-content-area {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        .col-lg-7 > .card.p-4:first-child #ip-input {
            flex: 1;
            min-height: 120px;
        }
        .col-lg-7 > .card.p-4:first-child .ip-actions-area {
            flex-shrink: 0;
        }
        /* 系统控制台卡片内部布局 - 固定高度，不自动扩展 */
        .col-lg-5 > .card.p-4 .console {
            height: 380px;
            max-height: 380px;
            flex-shrink: 0;
        }
        
        /* 响应式优化 */
        @media (max-width: 768px) {
            .card {
                border-radius: 16px;
                margin-bottom: 16px;
            }
            .card.p-3, .card.p-4 {
                padding: 1rem !important;
            }
            .row.g-2 {
                gap: 8px !important;
            }
            .input-group {
                flex-wrap: nowrap;
            }
            .input-group .btn {
                white-space: nowrap;
            }
            /* 筛选工具栏移动端适配 */
            .filter-toolbar {
                display: block !important;
            }
            .filter-line {
                grid-template-columns: 1fr 34px;
            }
            .filter-line .btn {
                padding: 7px 9px !important;
                font-size: 12px !important;
            }
            .filter-toolbar {
                gap: 6px !important;
            }
            .filter-toolbar .form-control-sm {
                min-width: 70px !important;
                flex: 1 1 35% !important;
                font-size: 11px !important;
                padding: 6px 8px !important;
            }
            .filter-toolbar .pool-stat {
                font-size: 10px !important;
                white-space: nowrap;
                flex-shrink: 0;
            }
        }
    </style>
</head>
<body class="pb-5">

<a href="https://github.com/231128ikun/DDNS-cf-proxyip" class="github-corner" aria-label="View source on GitHub" target="_blank">
    <svg viewBox="0 0 250 250" aria-hidden="true">
        <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
        <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
        <path d="M115.0,115.0 C114.9,115.1 118.7,116.6 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.6 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
</a>

<div class="container hero">
    <h1>
        🌐 DDNS Pro 多域名管理
    </h1>
    <div class="hero-actions">
        <div class="guide-toggle" onclick="toggleGuide()" title="使用步骤提示">?</div>
        <div class="config-info">
            🧭 建议流程：导入IP → 检测清洗 → 保存到池 → 执行维护
        </div>
    </div>
    ${kvReady ? '' : `<div class="kv-alert"><strong>KV 未绑定。</strong>请在 Worker Settings &gt; Bindings 中绑定 KV Namespace，变量名必须为 <code>IP_DATA</code>。未绑定前配置保存、IP 池、维护任务都不可用。</div>`}
    <div id="usage-guide" class="usage-guide" style="display:none">
        <ol>
            <li><strong>准备IP</strong>：在左侧 <code>IP库管理</code> 中手动输入或远程加载 IP，点击【⚡ 检测清洗】筛出可用 IP。</li>
            <li><strong>保存到池</strong>：选择上方的 IP 池（默认为通用池），点击【💾 保存到当前池】将可用 IP 入库。</li>
            <li><strong>执行维护</strong>：在顶部选择要维护的域名，点击右侧【🔧 执行全部维护】或依靠定时任务自动维护。</li>
        </ol>
    </div>
    <div class="domain-selector">
        <select id="domain-select" class="form-select" onchange="switchDomain()">
            ${C.targets.map((t, i) => {
                const modeLabel = {'A': 'A/AAAA', 'TXT': 'TXT'};
                const label = `${t.domain} · ${modeLabel[t.mode] || t.mode}${t.mode !== 'TXT' ? ' · ' + t.port : ''}`;
                return `<option value="${i}">${label}</option>`;
            }).join('')}
        </select>
    </div>
</div>

<div class="container">
    <div class="top-nav">
        <button class="nav-tab active" data-page="dashboard" onclick="showPage('dashboard')">运行面板</button>
        <button class="nav-tab" data-page="config" onclick="showPage('config')">配置中心</button>
    </div>

    <div id="page-dashboard" class="page-panel active">
    <!-- 解析实况 & Check ProxyIP -->
    <div class="card p-3">
        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <h6 class="m-0 fw-bold">📡 解析实况</h6>
            <div class="d-flex gap-2 align-items-center flex-grow-1" style="max-width:500px">
                <input type="text" id="lookup-domain" class="form-control form-control-sm" placeholder="探测: 域名 / IP:端口 / txt@域名" style="border-radius:8px">
                <button class="btn btn-info btn-sm text-white" onclick="lookupDomain()" title="探测任意域名或IP" style="white-space:nowrap">🔎</button>
                <button class="btn btn-primary btn-sm" onclick="refreshStatus()" title="刷新当前域名解析">🔄</button>
            </div>
        </div>
        
        <div id="manual-add-section" class="mb-2">
            <div class="input-group input-group-sm">
                <input type="text" id="manual-add-ip" class="form-control" placeholder="手动添加IP到当前域名 (如: 1.2.3.4:443)">
                <button class="btn btn-success" onclick="manualAddIP()" title="添加IP到当前域名">➕</button>
            </div>
        </div>
        
        <!-- 统一展示区域 -->
        <div id="status-display" class="scroll-box" style="max-height:320px">
            <div class="table-responsive">
                <table class="table text-center mb-0 status-table">
                    <thead style="position:sticky;top:0;background:#fff;z-index:1">
                        <tr>
                            <th>目标地址</th>
                            <th>延迟</th>
                            <th>状态</th>
                            <th>出口IP / 线路</th>
                            <th>Colo</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="status-table"></tbody>
                </table>
            </div>
            <div id="txt-status"></div>
        </div>
    </div>

    <div class="row">
        <!-- IP管理 -->
        <div class="col-lg-7">
            <div class="card p-4 mb-3">
                <!-- 池选择器和操作 -->
                <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                    <h6 class="m-0 fw-bold">📦 IP库管理</h6>
                    <div class="d-flex gap-1 align-items-center">
                        <select id="pool-selector" class="form-select form-select-sm" style="width:120px;border-radius:8px" onchange="switchPool()">
                            <option value="pool">通用池</option>
                        </select>
                        <button class="btn btn-sm" onclick="createNewPool()" title="新建池" style="padding:6px 8px">➕</button>
                        <button class="btn btn-sm" onclick="deleteCurrentPool()" title="删除池" style="padding:6px 8px">🗑️</button>
                        <button class="btn btn-sm" onclick="oneClickClean()" title="一键洗库" style="padding:6px 8px">🧹</button>
                    </div>
                </div>
                
                <!-- 内容区域 - 自动扩展 -->
                <div class="ip-content-area">
                    <!-- 加载区 -->
                    <div class="d-flex gap-2 mb-2 align-items-center">
                        <input type="text" id="remote-url" class="form-control form-control-sm flex-grow-1" placeholder="远程TXT URL" style="border-radius:8px">
                        <button class="btn btn-sm btn-outline-primary" onclick="loadRemoteUrl()" style="white-space:nowrap" title="从远程URL加载">🌐 加载</button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="loadCurrentPool()" title="加载当前池到输入框" style="white-space:nowrap">📂 从库</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="clearInput()" title="清空输入框" style="white-space:nowrap">🗑️ 清空</button>
                    </div>
                    
                    <!-- 输入区 -->
                    <textarea id="ip-input" class="form-control mb-2" rows="6" placeholder="支持格式：&#10;1.2.3.4:443&#10;1.2.3.4 (默认443端口)&#10;example.com:8443 (自动解析域名)&#10;1.2.3.4:443 #HK 香港节点 (带注释)" style="border-radius:12px;font-family:'SF Mono',monospace;font-size:12px"></textarea>
                    
                    <!-- 筛选工具 -->
                    <div class="mb-2 filter-toolbar">
                        <div class="filter-line">
                            <input type="text" id="universal-filter" class="form-control form-control-sm" style="border-radius:8px" placeholder="筛选">
                            <button class="filter-help-btn" onclick="toggleFilterHelp()" title="筛选用法">?</button>
                            <button class="btn btn-sm btn-outline-success" onclick="smartFilter('keep')" title="保留匹配的IP">保留</button>
                            <button class="btn btn-sm btn-outline-danger" onclick="smartFilter('exclude')" title="排除匹配的IP">排除</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="quickDeduplicate()" title="去除重复IP">去重</button>
                        </div>
                        <div id="filter-help" class="filter-help">
                            支持空格分隔条件：<code>port:443</code>、<code>port:443-2053</code>、<code>country:KR</code>、<code>asn:AS4766</code>、普通关键词。空格表示“且”，竖线 <code>|</code> 表示“或”，例如 <code>country:KR asn:AS4766 | country:US</code>。
                        </div>
                        <div id="filter-preview" class="filter-preview">输入条件后会显示匹配数量。</div>
                        <span class="text-secondary small pool-stat" title="当前池中IP数量">📊<span id="pool-count">0</span></span>
                    </div>
                </div>
                
                <!-- 底部按钮区域 - 固定在底部 -->
                <div class="ip-actions-area mt-auto">
                    <!-- 主操作按钮 -->
                    <div class="d-flex gap-2" id="main-actions">
                        <button id="btn-check" class="btn btn-primary flex-grow-1" onclick="batchCheck()" style="border-radius:10px">⚡ 检测</button>
                        <button class="btn btn-success flex-grow-1" onclick="saveToCurrentPool('append')" style="border-radius:10px">💾 入库</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="removeFromPool()" title="从库中移除输入框中的IP" style="border-radius:8px">从库中移除</button>
                    </div>
                    
                    <!-- 垃圾桶专用操作 -->
                    <div id="trash-actions" style="display:none" class="mt-2">
                        <div class="row g-2">
                            <div class="col-6">
                                <button class="btn btn-outline-success btn-sm w-100" onclick="restoreSelected()">♻️ 恢复选中</button>
                            </div>
                            <div class="col-6">
                                <button class="btn btn-outline-danger btn-sm w-100" onclick="clearTrash()">🗑️ 清空垃圾桶</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 域名池绑定 -->
            <div class="card p-4 mb-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h6 class="m-0 fw-bold">🔗 域名池绑定</h6>
                    <button class="btn btn-sm btn-outline-primary" onclick="loadDomainPoolMapping()">🔄 刷新</button>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>域名</th>
                                <th>绑定池</th>
                            </tr>
                        </thead>
                        <tbody id="domain-binding-list">
                            <tr><td colspan="2" class="text-center text-secondary">加载中...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
        </div>

        <!-- 控制台 -->
        <div class="col-lg-5">
            <div class="card p-4">
                <h6 class="mb-3 fw-bold">📊 系统控制台</h6>
                <div id="log-window" class="console mb-3"></div>
                <div class="progress mb-3" style="height:12px; background:#2c2c2e; border-radius:6px;">
                    <div id="pg-bar" class="progress-bar" style="width:0%; background:var(--success);"></div>
                </div>
                <button id="btn-maintain" class="btn btn-dark w-100" onclick="runMaintain()">🔧 执行全部维护</button>
            </div>
        </div>
    </div>
    </div>

    <div id="page-config" class="page-panel">
        <div class="card p-4 mb-3">
            <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                <h6 class="m-0 fw-bold">⚙️ 配置中心</h6>
                <button id="btn-save-config" class="btn btn-sm btn-success config-save-btn" onclick="saveAppConfig()" style="display:none">💾 保存改动</button>
            </div>
            <div class="switch-row mb-3">
                <label class="switch">
                    <input type="checkbox" id="cfg-scheduled-enabled">
                    <span class="switch-slider"></span>
                    <span>自动维护</span>
                </label>
                <label class="switch">
                    <input type="checkbox" id="cfg-tg-enabled">
                    <span class="switch-slider"></span>
                    <span>TG通知</span>
                </label>
            </div>
            <div class="config-grid mb-3">
                <label class="field span-2"><span>检测 API</span><small>主检测接口，支持 {proxyip} 占位符。</small><input id="cfg-check-api" class="form-control form-control-sm" placeholder="CHECK_API"></label>
                <label class="field span-2"><span>备用检测 API</span><small>复检或主接口失败时使用，可留空。</small><input id="cfg-check-api-backup" class="form-control form-control-sm" placeholder="CHECK_API_BACKUP"></label>
                <label class="field"><span>DoH API</span><small>域名解析查询接口。</small><input id="cfg-doh-api" class="form-control form-control-sm" placeholder="DOH_API"></label>
                <label class="field"><span>面板密钥</span><small>为空则关闭前端鉴权。</small><input id="cfg-auth-key" class="form-control form-control-sm" placeholder="AUTH_KEY"></label>
                <label class="field"><span>TG Bot Token</span><small>开启 TG 通知时必填。</small><input id="cfg-tg-token" class="form-control form-control-sm" placeholder="TG_TOKEN"></label>
                <label class="field"><span>TG Chat ID</span><small>通知接收账号或群组 ID。</small><input id="cfg-tg-id" class="form-control form-control-sm" placeholder="TG_ID"></label>
            </div>
        </div>

        <div class="card p-4 mb-3">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h6 class="m-0 fw-bold">🌐 维护的域名配置</h6>
                <button class="btn btn-sm btn-outline-primary" onclick="addZoneConfigRow()">➕ 添加权限配置</button>
            </div>
            <div id="zone-config-list" class="config-card-grid"></div>
            <div id="zone-edit-panel" class="config-edit-panel"></div>
        </div>

        <div class="card p-4 mb-3">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h6 class="m-0 fw-bold">🧭 管理域名</h6>
                <button class="btn btn-sm btn-outline-primary" onclick="addTargetConfigRow()">➕ 添加管理域名</button>
            </div>
            <div id="target-config-list" class="config-card-grid"></div>
            <div id="target-edit-panel" class="config-edit-panel"></div>
        </div>
    </div>
</div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>

<script>
    const TARGETS = ${targetsJson};
    const SETTINGS = ${settingsJson};
    const INITIAL_APP_CONFIG = ${appConfigJson};
    const AUTH_ENABLED = ${C.authKey ? 'true' : 'false'};
    const MODE_LABELS = {'A': 'A/AAAA', 'TXT': 'TXT'};
    let currentTargetIndex = 0;
    let currentPool = 'pool';
    let abortController = null;
    let domainPoolMapping = {};
    let availablePools = ['pool'];
    let toastTimer = null;
    let configDraft = null;
    let configDirty = false;
    
    // 检测中断状态
    let pausedCheckState = null; // { uncheckedLines: [], validIPs: [], total: number }
    
    
    // 自定义模态对话框
    function showCheckInterruptModal(stats) {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'custom-modal-overlay';
            overlay.innerHTML = \`
                <div class="custom-modal">
                    <div class="custom-modal-title">⏸️ 检测已中断</div>
                    <div class="custom-modal-stats">
                        <div><span class="label">已检测</span><span class="value">\${stats.checked} / \${stats.total}</span></div>
                        <div><span class="label">有效IP</span><span class="value">\${stats.valid} 个</span></div>
                        <div><span class="label">有效率</span><span class="value">\${stats.rate}%</span></div>
                        <div><span class="label">未检测</span><span class="value">\${stats.unchecked} 个</span></div>
                    </div>
                    <div class="custom-modal-buttons">
                        <button class="btn-abandon" id="modal-abandon">放弃检测</button>
                        <button class="btn-continue" id="modal-continue">继续</button>
                    </div>
                </div>
            \`;
            document.body.appendChild(overlay);
            
            document.getElementById('modal-continue').onclick = () => {
                document.body.removeChild(overlay);
                resolve(true);
            };
            document.getElementById('modal-abandon').onclick = () => {
                document.body.removeChild(overlay);
                resolve(false);
            };
        });
    }
    
    // 池名显示（统一格式）
    const POOL_NAMES = { pool: '通用池', pool_trash: '🗑️ 垃圾桶', domain_pool_mapping: '系统数据' };
    function getPoolName(key) { return POOL_NAMES[key] || key.replace('pool_', '') + '池'; }
    
    function getAuthTokenFromUrlOrStorage() {
        const urlKey = new URLSearchParams(location.search).get('key');
        if (urlKey && urlKey.trim()) {
            try { localStorage.setItem('ddns_auth_key', urlKey.trim()); } catch {}
            return urlKey.trim();
        }
        try {
            const stored = localStorage.getItem('ddns_auth_key');
            return stored ? stored.trim() : '';
        } catch {
            return '';
        }
    }
    
    function ensureAuthToken() {
        if (!AUTH_ENABLED) return '';
        let token = getAuthTokenFromUrlOrStorage();
        if (!token) {
            token = prompt('请输入 AUTH_KEY（已开启访问保护）');
            if (token && token.trim()) {
                token = token.trim();
                try { localStorage.setItem('ddns_auth_key', token); } catch {}
            } else {
                token = '';
            }
        }
        return token;
    }

    function setInputValue(id, value) {
        const el = document.getElementById(id);
        if (el) el.value = value || '';
    }

    function getInputValue(id) {
        const el = document.getElementById(id);
        return el ? el.value.trim() : '';
    }

    function showToast(message, type = 'success') {
        const el = document.getElementById('toast');
        if (!el) return;
        el.textContent = message;
        el.className = \`toast \${type} show\`;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            el.classList.remove('show');
        }, 2600);
    }

    async function copyText(value, label = '内容') {
        const text = String(value || '').trim();
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            showToast(label + '已复制');
            log('✓ 已复制' + label, 'success');
        } catch (e) {
            showToast('复制失败', 'error');
            log('✗ 复制失败: ' + e.message, 'error');
        }
    }

    function showPage(page) {
        document.querySelectorAll('.page-panel').forEach(el => el.classList.toggle('active', el.id === \`page-\${page}\`));
        document.querySelectorAll('.nav-tab').forEach(el => el.classList.toggle('active', el.dataset.page === page));
    }

    function bindConfigGlobalChangeHandlers() {
        ['cfg-scheduled-enabled', 'cfg-tg-enabled', 'cfg-check-api', 'cfg-check-api-backup', 'cfg-doh-api', 'cfg-auth-key', 'cfg-tg-token', 'cfg-tg-id'].forEach(id => {
            const el = document.getElementById(id);
            if (!el || el.dataset.dirtyBound) return;
            el.dataset.dirtyBound = '1';
            el.addEventListener('change', () => markConfigDirty('全局配置已变更，记得保存改动'));
            el.addEventListener('input', () => markConfigDirty());
        });
    }

    function cloneConfig(config) {
        return JSON.parse(JSON.stringify(config || {}));
    }

    function markConfigDirty(message) {
        configDirty = true;
        const btn = document.getElementById('btn-save-config');
        if (btn) btn.style.display = 'inline-block';
        if (message) showToast(message, 'info');
    }

    function clearConfigDirty() {
        configDirty = false;
        const btn = document.getElementById('btn-save-config');
        if (btn) btn.style.display = 'none';
    }

    function normalizeDraftZone(zone = {}, index = 0) {
        return {
            name: '配置' + (index + 1),
            label: String(zone.label || zone.baseDomain || ('配置' + (index + 1))).trim(),
            baseDomain: String(zone.baseDomain || '').trim(),
            zoneId: String(zone.zoneId || '').trim(),
            apiKey: String(zone.apiKey || '').trim()
        };
    }

    function getDraftZones() {
        if (!configDraft) configDraft = cloneConfig(INITIAL_APP_CONFIG);
        configDraft.zones = (Array.isArray(configDraft.zones) && configDraft.zones.length ? configDraft.zones : [{ label: '配置1' }])
            .map(normalizeDraftZone);
        return configDraft.zones;
    }

    function getZoneDisplayName(index) {
        const zone = getDraftZones()[index] || {};
        return [zone.name || ('配置' + (index + 1)), zone.label || zone.baseDomain].filter(Boolean).join(' · ');
    }

    function computeDomainFromTarget(target = {}) {
        const zones = getDraftZones();
        const zone = zones[parseInt(target.zoneIndex || 0, 10)] || zones[0] || {};
        const baseDomain = zone.baseDomain || target.baseDomain || '';
        const prefix = String(target.prefix || '').trim().replace(/^\\.+|\\.+$/g, '');
        return baseDomain ? (prefix ? prefix + '.' + baseDomain : baseDomain) : String(target.domain || '').trim();
    }

    function renderConfigCards() {
        renderZoneConfigRows(configDraft?.zones || []);
        renderTargetConfigRows(configDraft?.targets || []);
    }

    function renderZoneConfigRows(zones) {
        const list = document.getElementById('zone-config-list');
        if (!list) return;
        const rows = (Array.isArray(zones) && zones.length ? zones : [{ label: '配置1', baseDomain: '', zoneId: '', apiKey: '' }]).map(normalizeDraftZone);
        if (configDraft) configDraft.zones = rows;
        list.innerHTML = rows.map((zone, index) => buildZoneCard(zone, index)).join('');
    }

    function buildZoneCard(zone = {}, index = 0) {
        const title = zone.label || zone.baseDomain || zone.name || ('配置' + (index + 1));
        return \`
            <div class="config-mini-card" onclick="editZoneConfig(\${index})">
                <h5>\${escapeHTML(title)}</h5>
                <div class="meta"><span>\${escapeHTML(zone.name || ('配置' + (index + 1)))}</span><span>\${escapeHTML(zone.baseDomain || '未设置根域')}</span></div>
                <div class="meta"><span>Zone: \${escapeHTML(zone.zoneId ? '已填写' : '未填写')}</span><span>CF Key: \${escapeHTML(zone.apiKey ? '已填写' : '未填写')}</span></div>
                <div class="actions" onclick="event.stopPropagation()">
                    <button class="btn btn-outline-primary btn-sm" onclick="editZoneConfig(\${index})">编辑</button>
                    <button class="btn btn-outline-danger btn-sm" onclick="deleteZoneConfig(\${index})">删除</button>
                </div>
            </div>
        \`;
    }

    function addZoneConfigRow() {
        const zones = getDraftZones();
        showZoneEditor(zones.length, { label: '配置' + (zones.length + 1), baseDomain: '', zoneId: '', apiKey: '' });
    }

    function collectZoneConfigRows() {
        return getDraftZones().map(normalizeDraftZone).filter(zone => zone.baseDomain || zone.zoneId || zone.apiKey);
    }

    function getZoneOptionsHtml(selectedIndex) {
        const zones = getDraftZones();
        return zones.map((zone, index) => {
            const label = [zone.name || \`配置\${index + 1}\`, zone.label || zone.baseDomain].filter(Boolean).join(' · ');
            return \`<option value="\${index}" \${Number(selectedIndex) === index ? 'selected' : ''}>\${escapeHTML(label)}</option>\`;
        }).join('') || '<option value="">请先添加维护域名配置</option>';
    }

    function editZoneConfig(index) {
        showZoneEditor(index, getDraftZones()[index] || {});
    }

    function showZoneEditor(index, zone = {}) {
        const panel = document.getElementById('zone-edit-panel');
        if (!panel) return;
        const number = index + 1;
        panel.classList.add('active');
        panel.innerHTML = \`
            <h6 class="mb-3 fw-bold">\${index >= getDraftZones().length ? '添加' : '编辑'}权限配置</h6>
            <div class="config-edit-grid">
                <label class="field"><span>配置</span><small>自动编号。</small><input id="edit-zone-name" class="form-control form-control-sm" value="\${escapeHTML(zone.name || ('配置' + number))}" readonly></label>
                <label class="field"><span>别名</span><small>卡片显示名称。</small><input id="edit-zone-label" class="form-control form-control-sm" value="\${escapeHTML(zone.label || zone.baseDomain || ('配置' + number))}" placeholder="配置\${number}"></label>
                <label class="field"><span>维护根域</span><small>例如 dwb.cc.cd。</small><input id="edit-zone-base" class="form-control form-control-sm" value="\${escapeHTML(zone.baseDomain || '')}" placeholder="dwb.cc.cd"></label>
                <label class="field"><span>Zone ID</span><small>Cloudflare 区域 ID。</small><input id="edit-zone-id" class="form-control form-control-sm" value="\${escapeHTML(zone.zoneId || '')}" placeholder="Zone ID"></label>
                <label class="field span-2"><span>CF Key</span><small>需要 DNS 编辑权限。</small><input id="edit-zone-key" class="form-control form-control-sm" value="\${escapeHTML(zone.apiKey || '')}" placeholder="CF API Token"></label>
            </div>
            <div class="config-edit-actions">
                <button class="btn btn-outline-secondary btn-sm" onclick="closeConfigEditor('zone')">取消</button>
                <button class="btn btn-primary btn-sm" onclick="commitZoneEditor(\${index})">保存到页面</button>
            </div>
        \`;
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function commitZoneEditor(index) {
        const zones = getDraftZones();
        zones[index] = normalizeDraftZone({
            label: getInputValue('edit-zone-label'),
            baseDomain: getInputValue('edit-zone-base'),
            zoneId: getInputValue('edit-zone-id'),
            apiKey: getInputValue('edit-zone-key')
        }, index);
        configDraft.zones = zones;
        renderConfigCards();
        closeConfigEditor('zone');
        markConfigDirty('权限配置已更新，记得保存改动');
    }

    function deleteZoneConfig(index) {
        const zones = getDraftZones();
        if (!confirm('确认删除这个权限配置？相关管理域名会改到配置1。')) return;
        zones.splice(index, 1);
        configDraft.zones = (zones.length ? zones : [{ label: '配置1' }]).map(normalizeDraftZone);
        configDraft.targets = (configDraft.targets || []).map(target => ({
            ...target,
            zoneIndex: target.zoneIndex === index ? 0 : (target.zoneIndex > index ? target.zoneIndex - 1 : target.zoneIndex)
        }));
        renderConfigCards();
        closeConfigEditor('zone');
        markConfigDirty('权限配置已删除，记得保存改动');
    }

    function closeConfigEditor(type) {
        const panel = document.getElementById(type === 'zone' ? 'zone-edit-panel' : 'target-edit-panel');
        if (panel) {
            panel.classList.remove('active');
            panel.innerHTML = '';
        }
    }

    function renderTargetConfigRows(targets) {
        const list = document.getElementById('target-config-list');
        if (!list) return;
        const rows = (Array.isArray(targets) && targets.length ? targets : [{ mode: 'A', zoneIndex: 0, prefix: '', port: '443', minActive: 3 }]);
        if (configDraft) configDraft.targets = rows;
        list.innerHTML = rows.map((target, index) => buildTargetCard(target, index)).join('');
    }

    function buildTargetCard(target = {}, index = 0) {
        const mode = target.mode === 'TXT' ? 'TXT' : 'A';
        const domain = computeDomainFromTarget(target);
        const meta = mode === 'TXT' ? 'TXT' : 'A/AAAA · ' + (target.port || '443');
        const exitLabel = { any: '任意出口', v4: 'IPv4出口', v6: 'IPv6出口', dual: '双栈出口' }[target.exitFilter || 'any'] || '任意出口';
        const filters = [target.country ? '国家 ' + target.country : '', target.asn ? 'ASN ' + target.asn : ''].filter(Boolean).join(' · ');
        const enabled = target.enabled !== false;
        return \`
            <div class="config-mini-card" onclick="editTargetConfig(\${index})">
                <h5>\${escapeHTML(domain || '未生成域名')}</h5>
                <div class="meta"><span>\${escapeHTML(meta)}</span><span>\${escapeHTML(exitLabel)}</span><span>\${escapeHTML(getZoneDisplayName(target.zoneIndex || 0))}</span><span>\${enabled ? '维护开启' : '维护关闭'}</span></div>
                <div class="meta"><span>活跃数 \${escapeHTML(String(target.minActive ?? 3))}</span>\${filters ? '<span>' + escapeHTML(filters) + '</span>' : ''}</div>
                <div class="actions" onclick="event.stopPropagation()">
                    <label class="switch" title="单独控制这个域名是否参与维护">
                        <input type="checkbox" \${enabled ? 'checked' : ''} onchange="toggleTargetEnabled(\${index}, this.checked)">
                        <span class="switch-slider"></span>
                    </label>
                    <button class="btn btn-outline-primary btn-sm" onclick="editTargetConfig(\${index})">编辑</button>
                    <button class="btn btn-outline-danger btn-sm" onclick="deleteTargetConfig(\${index})">删除</button>
                </div>
            </div>
        \`;
    }

    function addTargetConfigRow() {
        showTargetEditor((configDraft?.targets || []).length, { mode: 'A', zoneIndex: 0, prefix: '', port: '443', minActive: 3 });
    }

    function loadAppConfigToForm(config) {
        configDraft = cloneConfig(config);
        setInputValue('cfg-check-api', config.checkApi);
        setInputValue('cfg-check-api-backup', config.checkApiBackup);
        setInputValue('cfg-doh-api', config.dohApi);
        setInputValue('cfg-auth-key', config.authKey);
        setInputValue('cfg-tg-token', config.tgToken);
        setInputValue('cfg-tg-id', config.tgId);
        const scheduledToggle = document.getElementById('cfg-scheduled-enabled');
        const tgToggle = document.getElementById('cfg-tg-enabled');
        if (scheduledToggle) scheduledToggle.checked = config.scheduledEnabled !== false;
        if (tgToggle) tgToggle.checked = config.tgEnabled !== false;
        renderConfigCards();
        bindConfigGlobalChangeHandlers();
        clearConfigDirty();
    }

    function collectTargetConfigRows() {
        return (configDraft?.targets || []).map(target => ({
            ...target,
            domain: computeDomainFromTarget(target)
        })).filter(target => target.domain);
    }

    function editTargetConfig(index) {
        showTargetEditor(index, (configDraft?.targets || [])[index] || {});
    }

    function showTargetEditor(index, target = {}) {
        const panel = document.getElementById('target-edit-panel');
        if (!panel) return;
        const mode = target.mode === 'TXT' ? 'TXT' : 'A';
        const modeOptions = ['A', 'TXT'].map(value => \`<option value="\${value}" \${mode === value ? 'selected' : ''}>\${MODE_LABELS[value]}</option>\`).join('');
        const exit = target.exitFilter || 'any';
        panel.classList.add('active');
        panel.innerHTML = \`
            <h6 class="mb-3 fw-bold">\${index >= (configDraft?.targets || []).length ? '添加' : '编辑'}管理域名</h6>
            <div class="config-edit-grid">
                <label class="field"><span>权限配置</span><small>选择配置1/2/3。</small><select id="edit-target-zone" class="form-select form-select-sm" onchange="updateTargetEditorPreview()">\${getZoneOptionsHtml(target.zoneIndex ?? 0)}</select></label>
                <label class="field"><span>维护类型</span><small>A/AAAA 或 TXT。</small><select id="edit-target-mode" class="form-select form-select-sm" onchange="updateTargetEditorPreview()">\${modeOptions}</select></label>
                <label class="field"><span>维护开关</span><small>关闭后跳过这个域名。</small><select id="edit-target-enabled" class="form-select form-select-sm"><option value="true" \${target.enabled !== false ? 'selected' : ''}>开启</option><option value="false" \${target.enabled === false ? 'selected' : ''}>关闭</option></select></label>
                <label class="field"><span>出口类型</span><small>由检测 API 实时判断。</small><select id="edit-target-exit" class="form-select form-select-sm"><option value="any" \${exit === 'any' ? 'selected' : ''}>任意</option><option value="v4" \${exit === 'v4' ? 'selected' : ''}>IPv4</option><option value="v6" \${exit === 'v6' ? 'selected' : ''}>IPv6</option><option value="dual" \${exit === 'dual' ? 'selected' : ''}>IPv4 & IPv6</option></select></label>
                <label class="field"><span>域名前缀</span><small>留空表示根域。</small><input id="edit-target-prefix" class="form-control form-control-sm" value="\${escapeHTML(target.prefix || '')}" placeholder="kr" oninput="updateTargetEditorPreview()"></label>
                <label class="field"><span>端口</span><small>A/AAAA 模式显示。</small><input id="edit-target-port" class="form-control form-control-sm" value="\${escapeHTML(target.port || '443')}" placeholder="443"></label>
                <label class="field"><span>活跃数</span><small>最小可用数量。</small><input id="edit-target-min" type="number" min="0" class="form-control form-control-sm" value="\${escapeHTML(String(target.minActive ?? 3))}" placeholder="3"></label>
                <label class="field"><span>国家</span><small>可选，例如 KR。</small><input id="edit-target-country" class="form-control form-control-sm" value="\${escapeHTML(target.country || '')}" placeholder="KR"></label>
                <label class="field"><span>ASN</span><small>可选，例如 AS4766。</small><input id="edit-target-asn" class="form-control form-control-sm" value="\${escapeHTML(target.asn || '')}" placeholder="AS4766"></label>
                <label class="field"><span>完整域名</span><small>自动生成，点击可复制。</small><code id="edit-target-preview" class="copyable" onclick="copyText(this.textContent, '域名')"></code></label>
            </div>
            <div class="config-edit-actions">
                <button class="btn btn-outline-secondary btn-sm" onclick="closeConfigEditor('target')">取消</button>
                <button class="btn btn-primary btn-sm" onclick="commitTargetEditor(\${index})">保存到页面</button>
            </div>
        \`;
        updateTargetEditorPreview();
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function getTargetEditorValue() {
        const zoneIndex = parseInt(getInputValue('edit-target-zone') || '0', 10) || 0;
        const prefix = getInputValue('edit-target-prefix').replace(/^\\.+|\\.+$/g, '');
        const port = getInputValue('edit-target-port') || '443';
        const minActive = parseInt(getInputValue('edit-target-min') || '3', 10) || 3;
        const mode = getInputValue('edit-target-mode') === 'TXT' ? 'TXT' : 'A';
        const target = {
            mode,
            zoneIndex,
            prefix,
            port,
            minActive,
            country: getInputValue('edit-target-country').toUpperCase(),
            asn: getInputValue('edit-target-asn').toUpperCase(),
            exitFilter: getInputValue('edit-target-exit') || 'any',
            enabled: getInputValue('edit-target-enabled') !== 'false'
        };
        target.domain = computeDomainFromTarget(target);
        return target;
    }

    function updateTargetEditorPreview() {
        const preview = document.getElementById('edit-target-preview');
        if (!preview) return;
        preview.textContent = computeDomainFromTarget(getTargetEditorValue()) || '未生成域名';
    }

    function commitTargetEditor(index) {
        const target = getTargetEditorValue();
        if (!target.domain || target.domain === '未生成域名') {
            showToast('请先填写权限配置和域名前缀', 'error');
            return;
        }
        if (!configDraft.targets) configDraft.targets = [];
        configDraft.targets[index] = target;
        renderConfigCards();
        closeConfigEditor('target');
        markConfigDirty('管理域名已更新，记得保存改动');
    }

    function deleteTargetConfig(index) {
        if (!confirm('确认删除这个管理域名？')) return;
        if (!configDraft.targets) configDraft.targets = [];
        configDraft.targets.splice(index, 1);
        renderConfigCards();
        closeConfigEditor('target');
        markConfigDirty('管理域名已删除，记得保存改动');
    }

    function toggleTargetEnabled(index, enabled) {
        if (!configDraft.targets || !configDraft.targets[index]) return;
        configDraft.targets[index].enabled = enabled;
        renderConfigCards();
        markConfigDirty(enabled ? '已开启该域名维护，记得保存改动' : '已关闭该域名维护，记得保存改动');
    }

    async function saveAppConfig() {
        const scheduledToggle = document.getElementById('cfg-scheduled-enabled');
        const tgToggle = document.getElementById('cfg-tg-enabled');
        const config = {
            zones: collectZoneConfigRows(),
            checkApi: getInputValue('cfg-check-api'),
            checkApiBackup: getInputValue('cfg-check-api-backup'),
            dohApi: getInputValue('cfg-doh-api'),
            authKey: getInputValue('cfg-auth-key'),
            tgToken: getInputValue('cfg-tg-token'),
            tgId: getInputValue('cfg-tg-id'),
            scheduledEnabled: scheduledToggle ? scheduledToggle.checked : true,
            tgEnabled: tgToggle ? tgToggle.checked : true,
            targets: collectTargetConfigRows()
        };
        try {
            const btn = document.getElementById('btn-save-config');
            if (btn) {
                btn.disabled = true;
                btn.textContent = '保存中...';
            }
            const r = await apiFetch('/api/save-config', {
                method: 'POST',
                body: JSON.stringify({ config })
            }).then(r => r.json());
            if (!r.success) {
                log(\`❌ 配置保存失败: \${r.error || '未知错误'}\`, 'error');
                showToast(r.error || '配置保存失败', 'error');
                return;
            }
            configDraft = cloneConfig(config);
            clearConfigDirty();
            log('✅ 配置已保存到 KV，刷新页面后生效', 'success');
            showToast('配置已保存到 KV');
        } catch (e) {
            log(\`❌ 配置保存失败: \${e.message}\`, 'error');
            showToast('配置保存失败', 'error');
        } finally {
            const btn = document.getElementById('btn-save-config');
            if (btn) {
                btn.disabled = false;
                btn.textContent = '💾 保存改动';
                if (configDirty) btn.style.display = 'inline-block';
            }
        }
    }

    async function apiFetch(path, options = {}) {
        const opts = { ...options };
        const headers = new Headers(opts.headers || {});
        headers.set('Accept', 'application/json');
        if (opts.body && !(opts.body instanceof FormData) && !headers.has('Content-Type')) {
            headers.set('Content-Type', 'application/json');
        }
        if (AUTH_ENABLED) {
            const token = ensureAuthToken();
            if (token) headers.set('Authorization', 'Bearer ' + token);
        }
        opts.headers = headers;
        
        const resp = await fetch(path, opts);
        if (resp.status === 401 && AUTH_ENABLED) {
            try { localStorage.removeItem('ddns_auth_key'); } catch {}
        }
        return resp;
    }

    function escapeHTML(str) {
        if (!str) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    function escapeJSString(str) {
        const slash = String.fromCharCode(92);
        return String(str || '')
            .split(slash).join(slash + slash)
            .split("'").join(slash + "'")
            .split(String.fromCharCode(10)).join(slash + 'n')
            .split(String.fromCharCode(13)).join('');
    }

    const log = (m, t='info', skipTimestamp=false) => {
        const w = document.getElementById('log-window');
        const colors = { success: '#32d74b', error: '#ff453a', info: '#64d2ff', warn: '#ffd60a' };

        let output;
        if (skipTimestamp) {
            output = \`<div style="color:\${colors[t]}">\${escapeHTML(m)}</div>\`;
        } else {
            const time = new Date().toLocaleTimeString('zh-CN');
            output = \`<div style="color:\${colors[t]}">[<span style="color:#8e8e93">\${time}</span>] \${escapeHTML(m)}</div>\`;
        }

        w.insertAdjacentHTML('beforeend', output);
        w.scrollTop = w.scrollHeight;
    };
    
    function normalizeIPFormat(input) {
        if (!input) return null;
        
        input = input.trim();
        
        // 分离注释
        let comment = '';
        let mainPart = input;
        const commentIndex = input.indexOf('#');
        if (commentIndex > 0) {
            mainPart = input.substring(0, commentIndex).trim();
            comment = input.substring(commentIndex);
        }
        const fields = mainPart.split(',').map(item => item.trim());
        if (fields.length > 1) {
            const normalizedAddress = normalizeIPFormat(fields[0]);
            if (!normalizedAddress) return null;
            const metaFields = fields.slice(1, 4).map(item => item || 'null');
            return [normalizedAddress.split('#')[0].trim(), ...metaFields].join(',') + comment;
        }
        if (/^\\[[0-9a-fA-F:]+\\]:\\d+$/.test(mainPart)) {
            return mainPart + comment;
        }
        if (/^[0-9a-fA-F:]+$/.test(mainPart) && mainPart.includes(':')) {
            return \`[\${mainPart.replace(/^\\[/, '').replace(/\\]$/, '')}]:443\${comment}\`;
        }
        
        // 已经是标准格式
        if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d+$/.test(mainPart)) {
            return mainPart + comment;
        }
        
        // 空格分隔
        const parts = mainPart.split(/\\s+/);
        if (parts.length === 2) {
            const ip = parts[0].trim();
            const port = parts[1].trim();
            
            if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(ip) && /^\\d+$/.test(port)) {
                return \`\${ip}:\${port}\${comment}\`;
            }
        }
        
        // 纯IP（默认443端口）
        if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(mainPart)) {
            return \`\${mainPart}:443\${comment}\`;
        }
        
        // 中文冒号
        const match = mainPart.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})：(\\d+)$/);
        if (match) {
            return \`\${match[1]}:\${match[2]}\${comment}\`;
        }
        
        return null;
    }

    function toggleGuide() {
        const box = document.getElementById('usage-guide');
        if (!box) return;
        box.style.display = box.style.display === 'none' || box.style.display === '' ? 'block' : 'none';
    }

    function formatIPInfo(ipInfo) {
        if (!ipInfo) return '';

        let html = '';
        if (ipInfo.country) {
            html += \`<span class="ip-info-tag">\${escapeHTML(ipInfo.country)}</span>\`;
        }
        if (ipInfo.asn) {
            html += \`<span class="ip-info-tag">\${escapeHTML(formatAsn(ipInfo.asn))}</span>\`;
        }
        return html;
    }

    function formatAsn(asn) {
        const text = String(asn || '').trim();
        if (!text) return '';
        return text.toUpperCase().startsWith('AS') ? text : 'AS' + text;
    }

    function formatExitInfo(exits) {
        if (!Array.isArray(exits) || exits.length === 0) return '';
        const ordered = [...exits].sort((a, b) => {
            const order = { ipv4: 0, v4: 0, ipv6: 1, v6: 1 };
            return (order[String(a.stack || '').toLowerCase()] ?? 9) - (order[String(b.stack || '').toLowerCase()] ?? 9);
        });
        return ordered.map(exit => {
            const stack = exit.stack ? exit.stack.toUpperCase() : 'EXIT';
            const location = [exit.country, exit.city].filter(Boolean).join(' · ');
            const network = [formatAsn(exit.asn), exit.asOrganization].filter(Boolean).join(' · ');
            return \`<div class="exit-detail">
                <span class="ip-info-tag exit-stack">\${escapeHTML(stack)}</span>
                <span class="exit-ip copyable" onclick="copyText('\${escapeJSString(exit.ip || '')}', '出口IP')" title="点击复制出口IP">\${escapeHTML(exit.ip || '-')}</span>
                <span class="ip-info-tag exit-field" title="\${escapeHTML(location || '-') }">\${escapeHTML(location || '-')}</span>
                <span class="ip-info-tag exit-field" title="\${escapeHTML(network || '-') }">\${escapeHTML(network || '-')}</span>
            </div>\`;
        }).join('');
    }

    function parseAddrParts(addr) {
        const value = String(addr || '').split('#')[0].split(',')[0].trim();
        if (!value) return { host: '', port: '443' };
        if (value.startsWith('[')) {
            const end = value.indexOf(']');
            const host = end >= 0 ? value.slice(1, end) : value.replace(/^\\[/, '');
            const portMatch = value.match(/\\]:(\\d+)$/);
            return { host, port: portMatch ? portMatch[1] : '443' };
        }
        const parts = value.split(':');
        if (parts.length === 2) return { host: parts[0], port: parts[1] || '443' };
        return { host: value, port: '443' };
    }

    function parsePoolLine(line) {
        const raw = String(line || '').trim();
        const beforeComment = raw.split('#')[0].trim();
        const fields = beforeComment.split(',').map(item => item.trim());
        return {
            address: fields[0] || '',
            asn: formatAsn(fields[1]) || 'null',
            country: fields[2] || 'null',
            stack: fields[3] || 'null',
            comment: raw.includes('#') ? raw.slice(raw.indexOf('#') + 1).trim() : ''
        };
    }

    function getPoolEntryKey(line) {
        return parsePoolLine(line).address;
    }

    function buildPoolLineFromCheckResult(addr, result) {
        const parsed = parseAddrParts(addr);
        const ip = result.proxyIP || parsed.host;
        const port = result.portRemote || parsed.port;
        const asn = result.asn || (Array.isArray(result.exits) ? Array.from(new Set(result.exits.map(exit => exit.asn).filter(Boolean))).join('/') : '') || 'null';
        const country = result.country || (Array.isArray(result.exits) ? Array.from(new Set(result.exits.map(exit => exit.country).filter(Boolean))).join('/') : '') || 'null';
        const host = String(ip || '').replace(/^\\[/, '').replace(/\\]$/, '');
        const address = host.includes(':') ? \`[\${host}]:\${port}\` : \`\${host}:\${port}\`;
        return \`\${address},\${formatAsn(asn) || 'null'},\${country || 'null'}\`;
    }

    function formatLatencyValue(value) {
        if (value === null || value === undefined || value === '' || value === '-') return '未知';
        const text = String(value).trim();
        return text.endsWith('ms') ? text : text + 'ms';
    }

    async function checkIPWithInfo(addr) {
        const r = await apiFetch(\`/api/check-ip?ip=\${encodeURIComponent(addr)}\`).then(r => r.json());
        return { ip: addr, success: r.success, colo: r.colo || 'N/A', time: r.responseTime || '-', exits: r.exits || [], proxyIP: r.proxyIP, portRemote: r.portRemote, ipInfo: r.ipInfo || null, asn: r.asn, country: r.country, stack: r.stack };
    }

    function renderIPRow(r, actionHTML) {
        const infoHtml = formatExitInfo(r.exits) || (r.ipInfo ? formatIPInfo(r.ipInfo) : '-');
        return \`<tr>
            <td class="fw-bold copyable" onclick="copyText('\${escapeJSString(r.ip)}', '维护地址')" title="点击复制">\${escapeHTML(r.ip)}</td>
            <td><span class="latency-badge" title="来自后端检测 API 返回的 responseTime，不是浏览器到节点的延迟">\${escapeHTML(formatLatencyValue(r.time))}</span></td>
            <td><span class="status-badge \${r.success?'ok':'bad'}">\${r.success?'可用':'失败'}</span></td>
            <td class="exit-list-cell">\${infoHtml}</td>
            <td><span class="colo-badge" title="Cloudflare 机房 / colo">\${escapeHTML(r.colo || 'N/A')}</span></td>
            <td>\${actionHTML}</td>
        </tr>\`;
    }

    function switchDomain() {
        currentTargetIndex = parseInt(document.getElementById('domain-select').value);
        const target = TARGETS[currentTargetIndex];
        log(\`切换到: \${target.domain} (\${target.mode})\`);
        
        const manualSection = document.getElementById('manual-add-section');
        manualSection.style.display = 'block';
        
        refreshStatus();
    }
    
    async function loadRemoteUrl() {
        const url = document.getElementById('remote-url').value.trim();
        if (!url) {
            log('❌ 请输入URL', 'error');
            return;
        }
        
        log(\`🌐 加载: \${url}\`, 'warn');
        try {
            const r = await apiFetch('/api/load-remote-url', {
                method: 'POST',
                body: JSON.stringify({ url })
            }).then(r => r.json());
            
            if (r.success) {
                document.getElementById('ip-input').value = r.ips || '';
                updateFilterPreview();
                log(\`✅ 成功: \${r.count} 个\`, 'success');
            } else {
                log(\`❌ 失败\`, 'error');
            }
        } catch (e) {
            log(\`❌ 出错\`, 'error');
        }
    }
    
    async function loadCurrentPool() {
        log(\`📂 加载 \${currentPool}...\`, 'info');
        
        try {
            const r = await apiFetch(\`/api/get-pool?poolKey=\${currentPool}\`).then(r => r.json());
            document.getElementById('ip-input').value = r.pool || '';
            document.getElementById('pool-count').innerText = r.count;
            updateFilterPreview();
            log(\`✅ 已加载 \${r.count} 个IP\`, 'success');
        } catch (e) {
            log('❌ 加载失败', 'error');
        }
    }
    
    async function saveToCurrentPool(mode = 'append') {
        const content = document.getElementById('ip-input').value;
        if (!content.trim()) {
            log('❌ 内容为空', 'error');
            return;
        }
        
        const modeLabel = mode === 'replace' ? '覆盖' : '追加';
        log(\`💾 \${modeLabel}到 \${getPoolName(currentPool)}...\`, 'warn');
        
        try {
            const r = await apiFetch('/api/save-pool', {
                method: 'POST',
                body: JSON.stringify({ pool: content, poolKey: currentPool, mode })
            }).then(r => r.json());
            
            if (r.success) {
                if (mode === 'replace') {
                    log(\`✅ \${r.message}\`, 'success');
                } else {
                    log(\`✅ 已追加 \${r.added} 个IP到 \${getPoolName(currentPool)}\`, 'success');
                }
                document.getElementById('pool-count').innerText = r.count;
                document.getElementById('ip-input').value = '';
                updateFilterPreview();
            } else {
                log(\`❌ 失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 保存失败\`, 'error');
        }
    }
    
    async function removeFromPool() {
        const content = document.getElementById('ip-input').value;
        if (!content.trim()) {
            log('❌ 内容为空', 'error');
            return;
        }
        
        if (!confirm(\`确认从 \${getPoolName(currentPool)} 中删除这些IP？\`)) return;
        
        log(\`🗑️ 从 \${getPoolName(currentPool)} 删除...\`, 'warn');
        
        try {
            const r = await apiFetch('/api/save-pool', {
                method: 'POST',
                body: JSON.stringify({ pool: content, poolKey: currentPool, mode: 'remove' })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ \${r.message}\`, 'success');
                document.getElementById('pool-count').innerText = r.count;
                document.getElementById('ip-input').value = '';
                updateFilterPreview();
            } else {
                log(\`❌ 失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 删除失败\`, 'error');
        }
    }
    
    async function showPoolInfo() {
        try {
            const r = await apiFetch(\`/api/get-pool?poolKey=\${currentPool}\`).then(r => r.json());
            document.getElementById('pool-count').innerText = r.count;
        } catch (e) {
            log('❌ 查询失败', 'error');
        }
    }
    
    async function batchCheck(useBackupApi = false) {
        const btn = document.getElementById('btn-check');
        const input = document.getElementById('ip-input');
        const lines = input.value.split('\\n').filter(i => i.trim());
        
        if (!lines.length) {
            log('❌ 请先输入IP', 'error');
            return 'abandoned';
        }

        if (abortController) {
            abortController.abort();
            abortController = null;
            btn.textContent = '⚡ 检测清洗';
            btn.classList.remove('btn-danger');
            btn.classList.add('btn-warning');
            log('🛑 已停止检测', 'warn');
            document.getElementById('pg-bar').style.width = '0%';
            return 'abandoned';
        }
        
        abortController = new AbortController();
        const signal = abortController.signal;
        
        btn.textContent = '🛑 停止检测';
        btn.classList.remove('btn-warning');
        btn.classList.add('btn-danger');
        
        let valid = [], total = lines.length, checked = 0;
        const pg = document.getElementById('pg-bar');
        let checkStatus = 'completed';
        
        log(\`🚀 开始检测 \${total} 个IP (并发: \${SETTINGS.CONCURRENT_CHECKS})\`, 'warn');
        log(\`💡 可随时中断，已验证的有效IP将自动保留\`, 'info');
        
        const chunkSize = SETTINGS.CONCURRENT_CHECKS;
        let wasAborted = false;
        
        try {
            for (let i = 0; i < lines.length; i += chunkSize) {
                if (signal.aborted) {
                    wasAborted = true;
                    break;
                }
                
                const chunk = lines.slice(i, i + chunkSize);
                
                await Promise.all(chunk.map(async (line) => {
                    if (signal.aborted) return;
                    
                    const item = line.trim();
                    if (!item) return;
                    
                    // 检测是否为域名格式 (example.com 或 example.com:443)
                    const domainMatch = item.match(/^([a-zA-Z0-9][-a-zA-Z0-9.]*\\.[a-zA-Z]{2,}):?(\\d+)?$/);
                    let checkTargets = [];
                    
                    if (domainMatch) {
                        // 域名格式：调用后端解析
                        const domain = domainMatch[1];
                        const port = domainMatch[2] || '443';
                        try {
                            const data = await apiFetch(\`/api/lookup-domain?domain=\${encodeURIComponent(domain + ':' + port)}\`).then(r => r.json());
                            if (data.ips && data.ips.length > 0) {
                                checkTargets = data.ips.map(ip => ip.includes(':') ? \`[\${ip.replace(/^\\[/, '').replace(/\\]$/, '')}]:\${port}\` : \`\${ip}:\${port}\`);
                                log(\`  🌐 \${domain} → \${data.ips.length} 个IP\`, 'info');
                            } else {
                                log(\`  ⚠️ 域名无解析: \${domain}\`, 'warn');
                                checked++;
                                pg.style.width = (checked / total * 100) + '%';
                                return;
                            }
                        } catch (e) {
                            log(\`  ⚠️ 域名解析失败: \${domain}\`, 'warn');
                            checked++;
                            pg.style.width = (checked / total * 100) + '%';
                            return;
                        }
                    } else {
                        // IP格式
                        const normalized = normalizeIPFormat(item);
                        if (!normalized) {
                            log(\`  ⚠️  格式错误: \${item}\`, 'warn');
                            checked++;
                            pg.style.width = (checked / total * 100) + '%';
                            return;
                        }
                        checkTargets = [getPoolEntryKey(normalized)];
                    }
                    
                    // 检测所有目标IP
                    for (const checkTarget of checkTargets) {
                        try {
                            const checkUrl = \`/api/check-ip?ip=\${encodeURIComponent(checkTarget)}\${useBackupApi ? '&useBackup=true' : ''}\`;
                            const r = await apiFetch(checkUrl, {
                                signal: signal
                            }).then(r => r.json());
                            
                            if (r.success) {
                                valid.push(buildPoolLineFromCheckResult(checkTarget, r));
                                log(\`  ✅ \${checkTarget} - \${r.colo} (\${r.responseTime}ms)\`, 'success');
                            } else {
                                log(\`  ❌ \${checkTarget}\`, 'error');
                            }
                        } catch (e) {
                            if (e.name !== 'AbortError') {
                                log(\`  ❌ \${checkTarget}\`, 'error');
                            }
                        }
                    }
                    
                    checked++;
                    if (!signal.aborted) {
                        pg.style.width = (checked / total * 100) + '%';
                    }
                }));
            }
            
            // 核心改进：无论是否中断，都保留有效IP
            if (valid.length > 0) {
                input.value = valid.join('\\n');
            }

            if (wasAborted) {
                const rate = valid.length > 0 ? ((valid.length / checked) * 100).toFixed(1) : '0.0';
                if (valid.length > 0) {
                    log(\`⏸️ 检测已中断，已保留 \${valid.length} 个有效IP (共检测 \${checked}/\${total}, 有效率 \${rate}%)\`, 'warn');
                } else {
                    log(\`⏸️ 检测已中断，尚未发现有效IP (已检测 \${checked}/\${total})\`, 'warn');
                }

                // 保存中断状态
                const uncheckedLines = lines.filter((line, idx) => idx >= checked);
                pausedCheckState = {
                    uncheckedLines,
                    validIPs: valid,
                    total: total
                };

                // 使用自定义模态对话框
                const continueAction = await showCheckInterruptModal({
                    checked,
                    total,
                    valid: valid.length,
                    rate,
                    unchecked: uncheckedLines.length
                });

                if (continueAction && pausedCheckState) {
                    checkStatus = await continueCheck();
                } else {
                    abandonCheck();
                    checkStatus = 'abandoned';
                }
            } else {
                if (valid.length > 0) {
                    const rate = ((valid.length / total) * 100).toFixed(1);
                    log(\`✅ 检测完成: \${valid.length}/\${total} 有效 (\${rate}%)\`, 'success');
                } else {
                    log(\`❌ 检测完成: 0/\${total} 有效\`, 'error');
                    input.value = '';
                }
                pausedCheckState = null;
            }
            
        } catch (e) {
            if (e.name !== 'AbortError') {
                log(\`❌ 出错: \${e.message}\`, 'error');
            }
            // 异常时也保留已验证的IP
            if (valid.length > 0) {
                input.value = valid.join('\\n');
                log(\`⚠️ 检测异常，已保留 \${valid.length} 个有效IP\`, 'warn');
            }
        } finally {
            abortController = null;
            updateFilterPreview();
            btn.textContent = '⚡ 检测清洗';
            btn.classList.remove('btn-danger');
            btn.classList.add('btn-warning');
            setTimeout(() => { pg.style.width = '0%'; }, 1000);
        }
        return checkStatus;
    }

    function clearInput() {
        const input = document.getElementById('ip-input');
        if (input.value.trim() && !confirm('确认清空输入框？')) return;
        input.value = '';
        updateFilterPreview();
        pausedCheckState = null;
        log('🗑️ 输入框已清空', 'info');
    }
    
    // 继续检测
    async function continueCheck() {
        if (!pausedCheckState || pausedCheckState.uncheckedLines.length === 0) {
            log('❌ 没有待检测的IP', 'error');
            return 'abandoned';
        }

        const input = document.getElementById('ip-input');
        // 将有效IP和未检测IP合并
        const newContent = [...pausedCheckState.validIPs, ...pausedCheckState.uncheckedLines].join('\\n');
        input.value = newContent;
        updateFilterPreview();

        log(\`🔄 继续检测剩余 \${pausedCheckState.uncheckedLines.length} 个IP\`, 'info');

        pausedCheckState = null;

        // 继续检测
        return await batchCheck(cleaningPool === 'pool_trash');
    }
    
    // 放弃检测
    function abandonCheck() {
        if (pausedCheckState && pausedCheckState.validIPs.length > 0) {
            const input = document.getElementById('ip-input');
            input.value = pausedCheckState.validIPs.join('\\n');
            updateFilterPreview();
            log(\`🚫 已放弃检测，保留 \${pausedCheckState.validIPs.length} 个有效IP在输入框\`, 'warn');
        } else {
            log(\`🚫 已放弃检测\`, 'warn');
        }

        pausedCheckState = null;
    }
    
    function quickDeduplicate() {
        const input = document.getElementById('ip-input');
        const lines = input.value.split('\\n').filter(l => l.trim());
        
        if (lines.length === 0) {
            log('❌ 输入为空', 'error');
            return;
        }
        
        const before = lines.length;
        const seen = new Map();
        
        // 去重逻辑：IP:PORT 相同即判断为重复，保留最后出现的
        lines.forEach(line => {
            const normalized = normalizeIPFormat(line);
            if (normalized) {
                // 使用 IP:PORT 作为唯一标识
                const key = getPoolEntryKey(normalized);
                seen.set(key, normalized);
            }
        });
        
        const unique = Array.from(seen.values());
        input.value = unique.join('\\n');
        updateFilterPreview();
        
        const removed = before - unique.length;
        if (removed > 0) {
            log(\`✅ 去重完成: \${before} → \${unique.length} (移除 \${removed} 个重复)\`, 'success');
        } else {
            log(\`✨ 无重复IP\`, 'info');
        }
    }
    
    async function refreshStatus() {
        const t = document.getElementById('status-table');
        const txtDiv = document.getElementById('txt-status');
            const colspan = '6';
        t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">🔄 查询中...</td></tr>\`;
        txtDiv.innerHTML = '';
        
        try {
            const data = await apiFetch(\`/api/current-status?target=\${currentTargetIndex}\`).then(r => r.json());
            
            if (data.error) {
                t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ \${escapeHTML(data.error)}<br><small>请检查 CF_KEY, CF_ZONEID 配置</small></td></tr>\`;
                return;
            }

            // 统一收集所有记录到表格中显示
            let allRows = [];

            // 地址记录
            if (data.mode === 'A' && data.aRecords && data.aRecords.length > 0) {
                data.aRecords.forEach(r => {
                    allRows.push(renderIPRow(
                        { ip: r.address || (r.ip + ':' + r.port), colo: r.colo, time: r.time, success: r.success, exits: r.exits, proxyIP: r.proxyIP, portRemote: r.portRemote, ipInfo: r.ipInfo },
                        \`<a href="javascript:deleteRecord('\${escapeJSString(r.id)}')" class="text-danger text-decoration-none small fw-bold">🗑️</a>\`
                    ));
                });
            }

            // TXT记录（统一显示在表格中）
            if (data.mode === 'TXT' && data.txtRecords && data.txtRecords.length > 0) {
                const record = data.txtRecords[0];
                record.ips.forEach(ip => {
                    allRows.push(renderIPRow(
                        ip,
                        \`<a href="javascript:deleteTxtIP('\${escapeJSString(record.id)}', '\${escapeJSString(ip.ip)}')" class="text-danger text-decoration-none small fw-bold">🗑️</a>\`
                    ));
                });
            }
            
            // 显示结果
            if (allRows.length === 0) {
                t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">暂无记录</td></tr>\`;
            } else {
                t.innerHTML = allRows.join('');
            }
        } catch (e) {
            t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ 查询失败<br><small>请检查网络连接和CF配置</small></td></tr>\`;
        }
    }
    
    async function manualAddIP() {
        const input = document.getElementById('manual-add-ip');
        const ip = input.value.trim();
        
        if (!ip) {
            log('❌ 请输入IP', 'error');
            return;
        }
        
        const target = TARGETS[currentTargetIndex];

        log(\`➕ 添加到\${MODE_LABELS[target.mode]}: \${ip}\`, 'info');
        
        try {
            const r = await apiFetch('/api/add-a-record', {
                method: 'POST',
                body: JSON.stringify({ ip, targetIndex: currentTargetIndex })
            }).then(r => r.json());
            
            if (r.success) {
                const mode = r.mode || 'A';
                log(\`✅ 成功添加到\${mode}记录 - \${r.colo} (\${r.time}ms)\`, 'success');
                input.value = '';
                updateFilterPreview();
                refreshStatus();
            } else {
                log(\`❌ 失败: \${r.error || '未知错误'}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 出错: \${e.message}\`, 'error');
        }
    }
    
    async function lookupDomain() {
        const input = document.getElementById('lookup-domain');
        const val = input.value.trim();
        
        if (!val) {
            log('❌ 请输入', 'error');
            return;
        }
        
        log(\`🔍 探测: \${val}\`, 'info');
        
        const t = document.getElementById('status-table');
        const txtDiv = document.getElementById('txt-status');
        const colspan = '6';
        t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">🔄 探测中...</td></tr>\`;
        txtDiv.innerHTML = '';
        
        try {
            if (val.startsWith('txt@')) {
                const data = await apiFetch(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`).then(r => r.json());
                
                // null 检查
                if (!data.ips || !Array.isArray(data.ips)) {
                    log(\`❌ TXT 查询失败\`, 'error');
                    t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ TXT 查询失败</td></tr>\`;
                    return;
                }
                
                log(\`📝 TXT: \${data.ips.length} 个IP\`, 'success');
                
                // 并发检测（与地址记录探测统一模板）
                const checkResults = await Promise.all(data.ips.map(ip => checkIPWithInfo(ip)));

                // 显示在表格中（与地址记录探测统一模板）
                t.innerHTML = checkResults.map(r => renderIPRow(r,
                    \`<button class="btn btn-sm btn-outline-primary" onclick="addToInput('\${escapeHTML(buildPoolLineFromCheckResult(r.ip, r))}')" title="添加到输入框">➕</button>\`
                )).join('');
                
                const activeCount = checkResults.filter(r => r.success).length;
                log(\`📊 探测完成: \${activeCount}/\${data.ips.length} 活跃\`, activeCount === data.ips.length ? 'success' : (activeCount > 0 ? 'warn' : 'error'));
                return;
            }
            
            const isIP = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?$/.test(val) || /^\\[[0-9a-fA-F:]+\\](:\\d+)?$/.test(val) || (/^[0-9a-fA-F:]+$/.test(val) && val.includes(':'));
            let targets = [];
            
            if (isIP) {
                const normalized = normalizeIPFormat(val);
                targets = [normalized ? getPoolEntryKey(normalized) : val];
            } else {
                const data = await apiFetch(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`).then(r => r.json());
                
                if (!data.ips || !Array.isArray(data.ips) || data.ips.length === 0) {
                    log(\`⚠️ 域名无A/AAAA记录\`, 'warn');
                    t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">域名无A/AAAA记录</td></tr>\`;
                    return;
                }
                
                targets = data.ips.map(ip => ip.includes(':') ? \`[\${ip.replace(/^\\[/, '').replace(/\\]$/, '')}]:\${data.port || '443'}\` : \`\${ip}:\${data.port || '443'}\`);
                log(\`📡 \${data.ips.length} 个IP (端口: \${data.port || '443'})\`, 'success');
            }
            
            // 并发检测
            const checkResults = await Promise.all(targets.map(addr => checkIPWithInfo(addr)));

            // 显示在表格中
            t.innerHTML = checkResults.map(r => renderIPRow(r,
                \`<button class="btn btn-sm btn-outline-primary" onclick="addToInput('\${escapeHTML(buildPoolLineFromCheckResult(r.ip, r))}')" title="添加到输入框">➕</button>\`
            )).join('');
            
            const activeCount = checkResults.filter(r => r.success).length;
            log(\`📊 探测完成: \${activeCount}/\${targets.length} 活跃\`, activeCount === targets.length ? 'success' : (activeCount > 0 ? 'warn' : 'error'));
        } catch (e) {
            log(\`❌ 失败: \${e.message}\`, 'error');
            t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ 探测失败</td></tr>\`;
        }
    }
    
    function addToInput(ip) {
        const input = document.getElementById('ip-input');
        const lines = input.value.split('\\n').filter(l => l.trim());
        
        if (!lines.includes(ip)) {
            input.value = lines.concat([ip]).join('\\n');
            updateFilterPreview();
            log(\`✅ 已添加: \${ip}\`, 'success');
        } else {
            log(\`⚠️  已存在\`, 'warn');
        }
    }
    
    async function deleteRecord(id) {
        if (!confirm('确认删除？')) return;

        try {
            await apiFetch(\`/api/delete-record?id=\${encodeURIComponent(id)}&target=\${currentTargetIndex}\`, {
                method: 'POST'
            });
            log('🗑️  已删除', 'success');
            refreshStatus();
        } catch (e) {
            log(\`❌ 失败\`, 'error');
        }
    }

    async function deleteTxtIP(recordId, ip) {
        if (!confirm(\`确认删除 \${ip}？\`)) return;

        try {
            await apiFetch(\`/api/delete-record?id=\${encodeURIComponent(recordId)}&ip=\${encodeURIComponent(ip)}&isTxt=true&target=\${currentTargetIndex}\`, {
                method: 'POST'
            });
            log('🗑️ 已从TXT记录删除', 'success');
            refreshStatus();
        } catch (e) {
            log(\`❌ 删除失败\`, 'error');
        }
    }
    
    async function runMaintain() {
        log('🔧 启动维护...', 'warn');
        
        try {
            const r = await apiFetch('/api/maintain?manual=true',{
                method: 'POST'
            }).then(r => r.json());
            
            const allLogs = Array.isArray(r.allLogs)
                ? r.allLogs
                : (Array.isArray(r.reports) ? r.reports.flatMap(report => [
                    ...(report.logs || []),
                    ...(report.txtLogs || [])
                ]) : []);
            if (allLogs.length > 0) {
                allLogs.forEach(msg => log(msg, 'info', true));
            }
            
            log(\`✅ 维护完成，耗时: \${r.processingTime}ms\`, 'success');
            
            if (r.tgStatus) {
                switch (r.tgStatus.reason) {
                    case 'success':
                        log(\`📱 TG通知发送成功\`, 'success');
                        break;
                    case 'not_configured':
                        log(\`📱 TG未配置，跳过通知\`, 'info');
                        break;
                    case 'config_error':
                        log(\`📱 TG配置错误，发送失败 - \${r.tgStatus.message}\`, 'error');
                        if (r.tgStatus.detail) {
                            log(\`   详情: \${r.tgStatus.detail}\`, 'error');
                        }
                        break;
                    case 'network_error':
                        log(\`📱 TG发送失败，网络错误 - \${r.tgStatus.detail}\`, 'error');
                        break;
                    case 'no_need':
                        log(\`📱 无需通知（无变化）\`, 'info');
                        break;
                    default:
                        log(\`📱 未发送通知\`, 'info');
                }
            }
            
            refreshStatus();
            showPoolInfo();
        } catch (e) {
            log(\`❌ 维护失败: \${e.message}\`, 'error');
        }
    }
    
    async function loadDomainPoolMapping() {
        try {
            const r = await apiFetch('/api/get-domain-pool-mapping').then(r => r.json());
            domainPoolMapping = r.mapping || {};
            availablePools = r.pools || ['pool'];
            
            updatePoolSelector();
            updateDomainBindingTable();
            log('✅ 已加载池配置', 'success');
        } catch (e) {
            log('❌ 加载配置失败', 'error');
        }
    }
    
    function updatePoolSelector() {
        const selector = document.getElementById('pool-selector');
        
        const pools = ['pool'];
        const hasTrash = availablePools.includes('pool_trash');
        if (hasTrash) {
            pools.push('pool_trash');
        }
        
        availablePools.forEach(p => {
            if (p !== 'pool' && p !== 'pool_trash' && p !== 'domain_pool_mapping') {
                pools.push(p);
            }
        });
        
        if (!hasTrash) {
            pools.splice(1, 0, 'pool_trash');
        }
        
        selector.innerHTML = pools.map(pool => \`<option value="\${escapeHTML(pool)}">\${escapeHTML(getPoolName(pool))}</option>\`).join('');
        selector.value = currentPool;
    }
    
    function updateDomainBindingTable() {
        const tbody = document.getElementById('domain-binding-list');
        const domains = TARGETS.map(t => t.domain);
        
        tbody.innerHTML = domains.map(domain => {
            const boundPool = domainPoolMapping[domain] || 'pool';
            
            const selectablePools = availablePools.filter(p => 
                p !== 'pool_trash' && p !== 'domain_pool_mapping'
            );
            
            const options = selectablePools.map(pool => {
                const selected = pool === boundPool ? 'selected' : '';
                return \`<option value="\${escapeHTML(pool)}" \${selected}>\${escapeHTML(getPoolName(pool))}</option>\`;
            }).join('');

            return \`
                <tr>
                    <td><code>\${escapeHTML(domain)}</code></td>
                    <td>
                        <select class="form-select form-select-sm"
                                onchange="bindDomainToPool('\${escapeHTML(domain)}', this.value)">
                            \${options}
                        </select>
                    </td>
                </tr>
            \`;
        }).join('');
    }
    
    async function createNewPool() {
        const name = prompt('输入池名称 (支持中文、字母、数字、下划线、横杠)');
        if (!name) return;
        
        // 放宽限制：支持中文
        if (!/^[\u4e00-\u9fa5a-zA-Z0-9_-]+$/.test(name)) {
            alert('池名称只能包含中文、字母、数字、下划线、横杠!');
            return;
        }
        
        if (name.length > 40) {
            alert('池名称不能超过40个字符!');
            return;
        }
        
        const poolKey = \`pool_\${name}\`;
        
        if (availablePools.includes(poolKey)) {
            alert('池已存在!');
            return;
        }
        
        try {
            const r = await apiFetch('/api/create-pool', {
                method: 'POST',
                body: JSON.stringify({ poolKey })
            }).then(r => r.json());
            
            if (r.success) {
                availablePools.push(poolKey);
                currentPool = poolKey;
                updatePoolSelector();
                updateDomainBindingTable();
                log(\`✅ 已创建池: \${poolKey}\`, 'success');
            } else {
                alert(r.error || '创建失败');
            }
        } catch (e) {
            log('❌ 创建池失败', 'error');
        }
    }
    
    async function deleteCurrentPool() {
        const protectedPools = ['pool', 'pool_trash', 'domain_pool_mapping'];
        if (protectedPools.includes(currentPool)) {
            alert(\`不能删除\${getPoolName(currentPool)}!\`);
            return;
        }
        
        if (!confirm(\`确认删除 \${currentPool}?\`)) return;
        
        try {
            const r = await apiFetch(\`/api/delete-pool?poolKey=\${currentPool}\`, {
                method: 'POST'
            }).then(r => r.json());
            
            if (!r.success) {
                log(\`❌ 删除失败: \${r.error || '未知错误'}\`, 'error');
                return;
            }
            
            availablePools = availablePools.filter(p => p !== currentPool);
            currentPool = 'pool';
            updatePoolSelector();
            updateDomainBindingTable();
            log(\`✅ 已删除池\`, 'success');
        } catch (e) {
            log('❌ 删除失败', 'error');
        }
    }
    
    function switchPool() {
        currentPool = document.getElementById('pool-selector').value;
        log(\`📦 切换到: \${getPoolName(currentPool)}\`, 'info');
        
        const trashActions = document.getElementById('trash-actions');
        if (trashActions) {
            if (currentPool === 'pool_trash') {
                trashActions.style.display = 'block';
            } else {
                trashActions.style.display = 'none';
            }
        }
        
        showPoolInfo();
    }
    
    async function bindDomainToPool(domain, poolKey) {
        domainPoolMapping[domain] = poolKey;
        
        try {
            await apiFetch('/api/save-domain-pool-mapping', {
                method: 'POST',
                body: JSON.stringify({ mapping: domainPoolMapping })
            });
            
            log(\`✅ \${domain} → \${getPoolName(poolKey)}\`, 'success');
        } catch (e) {
            log('❌ 绑定失败', 'error');
        }
    }
    
    async function clearTrash() {
        if (!confirm('确认清空垃圾桶？此操作不可恢复！')) return;
        
        try {
            const r = await apiFetch('/api/clear-trash', { method: 'POST' }).then(r => r.json());
            if (r.success) {
                log('✅ 垃圾桶已清空', 'success');
                loadCurrentPool();
            }
        } catch (e) {
            log('❌ 清空失败', 'error');
        }
    }
    
    // 一键洗库状态
    let cleaningPool = null;
    let cleaningOriginalCount = 0;
    
    // 一键洗库：加载池 → 检测 → 自动保存
    // 普通池：有效IP覆盖保存，失效IP移入垃圾桶
    // 垃圾桶：有效IP恢复到原来的库
    async function oneClickClean() {
        const isTrash = currentPool === 'pool_trash';
        
        log(\`🧹 开始一键洗库: \${getPoolName(currentPool)}\`, 'warn');
        cleaningPool = currentPool;
        
        // 1. 加载池
        let allIPs = [];
        let originalLines = []; // 保存原始行（包含注释）
        try {
            const r = await apiFetch(\`/api/get-pool?poolKey=\${currentPool}\`).then(r => r.json());
            if (!r.pool || !r.pool.trim()) {
                log('❌ 池为空，无需清洗', 'error');
                cleaningPool = null;
                return;
            }
            originalLines = r.pool.split('\\n').filter(l => l.trim());
            allIPs = [...originalLines];
            document.getElementById('ip-input').value = r.pool;
            updateFilterPreview();
            cleaningOriginalCount = r.count;
            log(\`📂 已加载 \${r.count} 个IP\`, 'info');
        } catch (e) {
            log('❌ 加载失败', 'error');
            cleaningPool = null;
            return;
        }

        // 2. 检测（等待检测完成或中断）
        // 垃圾桶复检时使用备用接口（如有）独立验证
        const checkResult = await batchCheck(isTrash);

        // 3. 只有完全检测完成才自动保存，中断或放弃则不保存
        const content = document.getElementById('ip-input').value;
        const validLines = content.trim() ? content.trim().split('\\n') : [];
        const validCount = validLines.length;

        // 检查是否被中断或放弃
        if (checkResult !== 'completed') {
            // 检测被中断或放弃，不自动保存
            log(\`⚠️ 洗库被中断，有效IP保留在输入框，未自动保存\`, 'warn');
        } else if (cleaningPool) {
            if (isTrash) {
                // 垃圾桶洗库：有效IP恢复到原来的库
                await saveTrashCleanResult(validLines, originalLines);
            } else {
                // 普通池洗库：有效IP覆盖保存，失效IP移入垃圾桶
                await savePoolCleanResult(validLines, originalLines);
            }
        }
        
        cleaningPool = null;
        cleaningOriginalCount = 0;
    }
    
    // 普通池洗库结果保存：有效IP覆盖保存，失效IP移入垃圾桶
    async function savePoolCleanResult(validLines, originalLines) {
        const validCount = validLines.length;
        
        // 找出失效的IP（原始IP - 有效IP）
        const validKeys = new Set(validLines.map(line => {
            const normalized = normalizeIPFormat(line);
            return normalized ? getPoolEntryKey(normalized) : '';
        }).filter(k => k));
        
        const invalidLines = originalLines.filter(line => {
            const normalized = normalizeIPFormat(line);
            const key = normalized ? getPoolEntryKey(normalized) : '';
            return key && !validKeys.has(key);
        });
        
        try {
            // 1. 保存有效IP到池（覆盖）
            if (validCount > 0) {
                const r = await apiFetch('/api/save-pool', {
                    method: 'POST',
                    body: JSON.stringify({ pool: validLines.join('\\n'), poolKey: cleaningPool, mode: 'replace' })
                }).then(r => r.json());
                
                if (r.success) {
                    log(\`✅ 洗库完成: \${r.message}\`, 'success');
                    document.getElementById('pool-count').innerText = r.count;
                } else {
                    log(\`❌ 保存失败: \${r.error}\`, 'error');
                    return;
                }
            } else {
                // 清空池
                await apiFetch('/api/save-pool', {
                    method: 'POST',
                    body: JSON.stringify({ pool: '', poolKey: cleaningPool, mode: 'replace' })
                });
                log(\`⚠️ 洗库完成，无有效IP，池已清空\`, 'warn');
                document.getElementById('pool-count').innerText = '0';
            }
            
            // 2. 失效IP移入垃圾桶
            if (invalidLines.length > 0) {
                const trashContent = invalidLines.map(line => {
                    const normalized = normalizeIPFormat(line);
                    const key = normalized ? getPoolEntryKey(normalized) : getPoolEntryKey(line);
                    return \`\${key} # 洗库失效 \${new Date().toISOString()} 来自 \${cleaningPool}\`;
                }).join('\\n');
                
                await apiFetch('/api/save-pool', {
                    method: 'POST',
                    body: JSON.stringify({ pool: trashContent, poolKey: 'pool_trash', mode: 'append' })
                });
                
                log(\`🗑️ 已将 \${invalidLines.length} 个失效IP移入垃圾桶\`, 'info');
            }
            
            document.getElementById('ip-input').value = '';
            updateFilterPreview();
        } catch (e) {
            log(\`❌ 保存失败\`, 'error');
        }
    }
    
    // 垃圾桶洗库结果保存：有效IP恢复到原来的库
    async function saveTrashCleanResult(validLines, originalLines) {
        if (validLines.length === 0) {
            log(\`⚠️ 洗库完成，无有效IP可恢复\`, 'warn');
            document.getElementById('ip-input').value = '';
            updateFilterPreview();
            return;
        }
        
        // 提取有效IP的key
        const validKeys = new Set(validLines.map(line => {
            const normalized = normalizeIPFormat(line);
            return normalized ? getPoolEntryKey(normalized) : '';
        }).filter(k => k));
        
        // 从原始行中找到对应的完整条目（包含来源信息）
        const ipsToRestore = [];
        originalLines.forEach(line => {
            const normalized = normalizeIPFormat(line);
            const key = normalized ? getPoolEntryKey(normalized) : '';
            if (key && validKeys.has(key)) {
                ipsToRestore.push(key);
            }
        });
        
        try {
            // 调用恢复API
            const r = await apiFetch('/api/restore-from-trash', {
                method: 'POST',
                body: JSON.stringify({ ips: ipsToRestore, restoreToSource: true })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ 垃圾桶洗库完成: \${r.message}\`, 'success');
                document.getElementById('ip-input').value = '';
                updateFilterPreview();
                // 刷新垃圾桶数量
                showPoolInfo();
            } else {
                log(\`❌ 恢复失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 恢复失败\`, 'error');
        }
    }
    
    async function restoreSelected() {
        const content = document.getElementById('ip-input').value;
        const lines = content.split('\\n').filter(l => l.trim());
        
        if (lines.length === 0) {
            log('❌ 请先选择要恢复的IP', 'error');
            return;
        }
        
        const ips = lines.map(line => {
            const parts = line.split('#');
            return parts[0].trim();
        }).filter(ip => ip);
        
        try {
            const r = await apiFetch('/api/restore-from-trash', {
                method: 'POST',
                body: JSON.stringify({ ips, restoreToSource: true })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ \${r.message}\`, 'success');
                loadCurrentPool();
                updateFilterPreview();
            } else {
                log(\`❌ \${r.error}\`, 'error');
            }
        } catch (e) {
            log('❌ 恢复失败', 'error');
        }
    }
 
    function smartFilter(mode) {
        const input = document.getElementById('ip-input');
        const criteria = parseFilterExpression(getInputValue('universal-filter'));
        
        if (!criteria) {
            log('❌ 请至少填写一个筛选条件', 'error');
            return;
        }
        
        const lines = input.value.split('\\n').filter(l => l.trim());
        const filtered = lines.filter(line => {
            const matched = lineMatchesUniversalFilter(line, criteria);
            return mode === 'keep' ? matched : !matched;
        });
        
        input.value = filtered.join('\\n');
        updateFilterPreview();
        log(\`✅ 筛选完成: \${lines.length} → \${filtered.length}\`, 'success');
    }

    function parseUniversalFilter(query) {
        const tokens = String(query || '').split(/[\s,]+/).map(v => v.trim()).filter(Boolean);
        if (!tokens.length) return null;
        const criteria = { ports: [], countries: [], asns: [], text: [] };
        for (const token of tokens) {
            const match = token.match(/^([a-zA-Z]+):(.*)$/);
            if (!match) {
                criteria.text.push(token.toLowerCase());
                continue;
            }
            const key = match[1].toLowerCase();
            const value = match[2].trim();
            if (!value) continue;
            if (key === 'port') {
                const parsed = parsePortFilter(value);
                if (!parsed) return null;
                criteria.ports.push(...parsed);
            } else if (key === 'country') {
                criteria.countries.push(value.toUpperCase());
            } else if (key === 'asn' || key === 'as') {
                criteria.asns.push(value.replace(/^AS/i, '').toUpperCase());
            } else {
                criteria.text.push(value.toLowerCase());
            }
        }
        return criteria;
    }

    function parseFilterExpression(query) {
        const groups = String(query || '').split('|').map(part => parseUniversalFilter(part)).filter(Boolean);
        return groups.length ? groups : null;
    }

    function lineMatchesUniversalFilter(line, criteria) {
        const meta = parsePoolLine(line);
        const portNum = parseInt(parseAddrParts(meta.address).port, 10);
        const searchable = [meta.asn, meta.country, meta.comment, line].join(' ').toLowerCase();
        if (Array.isArray(criteria)) return criteria.some(group => lineMatchesUniversalFilter(line, group));
        if (criteria.ports.length && !criteria.ports.some(p => typeof p === 'number' ? portNum === p : portNum >= p.start && portNum <= p.end)) return false;
        const countryValues = String(meta.country || '').toUpperCase().split(/[\/,\s]+/).filter(Boolean);
        if (criteria.countries.length && !criteria.countries.some(country => countryValues.includes(country))) return false;
        const asn = String(meta.asn || '').replace(/^AS/i, '').toUpperCase();
        if (criteria.asns.length && !criteria.asns.includes(asn)) return false;
        if (criteria.text.length && !criteria.text.some(token => searchable.includes(token))) return false;
        return true;
    }

    function updateFilterPreview() {
        const preview = document.getElementById('filter-preview');
        if (!preview) return;
        const input = document.getElementById('ip-input');
        const lines = input ? input.value.split('\\n').filter(l => l.trim()) : [];
        const criteria = parseFilterExpression(getInputValue('universal-filter'));
        if (!criteria) {
            preview.innerHTML = '输入条件后会显示匹配数量。';
            return;
        }
        const matched = lines.filter(line => lineMatchesUniversalFilter(line, criteria)).length;
        preview.innerHTML = \`当前输入 <strong>\${lines.length}</strong> 条，匹配 <strong>\${matched}</strong> 条。\`;
    }

    function toggleFilterHelp() {
        const el = document.getElementById('filter-help');
        if (el) el.classList.toggle('active');
    }
    
    function parsePortFilter(portStr) {
        const parts = portStr.split(',').map(p => p.trim()).filter(p => p);
        const result = [];
        
        for (const part of parts) {
            if (part.includes('-')) {
                const [start, end] = part.split('-').map(p => parseInt(p.trim()));
                if (!start || !end || start < 1 || end > 65535 || start > end) {
                    return null;
                }
                result.push({ start, end });
            } else if (/^\\d+$/.test(part)) {
                const portNum = parseInt(part);
                if (portNum < 1 || portNum > 65535) {
                    return null;
                }
                result.push(portNum);
            } else {
                return null;
            }
        }
        
        return result.length > 0 ? result : null;
    }
    
    window.addEventListener('DOMContentLoaded', () => {
        log('🚀 系统就绪', 'success');
        log(\`⚙️ 配置: 并发\${SETTINGS.CONCURRENT_CHECKS} | 超时\${SETTINGS.CHECK_TIMEOUT}ms\`, 'info');
        loadAppConfigToForm(INITIAL_APP_CONFIG);
        ['ip-input', 'universal-filter'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', updateFilterPreview);
        });
        updateFilterPreview();
        switchDomain();
        Promise.all([
            showPoolInfo(),
            loadDomainPoolMapping()
        ]).catch(e => log('⚠️ 初始化部分失败', 'error'));
    });
</script>
<footer class="container text-center text-secondary small py-3">DDNS Pro · ${version}</footer>
</body>
</html>`;
    // 压缩HTML空白，减少传输体积约20-30%
    return html
        .replace(/^[ \t]+/gm, '')
        .replace(/\n{2,}/g, '\n');
}
