/**
 * DDNS Pro & Proxy IP Manager v6.9
 */

// ==================== 默认配置（环境变量未设置时使用） ====================
const DEFAULT_CONFIG = {
    // 目标维护域名的Cloudflare 配置
    apiKey: '',              // CF_KEY: Cloudflare API Token
    zoneId: '',              // CF_ZONEID: Cloudflare Zone ID
    
    // 目标维护域名的配置
    targets: [],             // CF_DOMAIN: 域名配置（解析后的目标列表）
    
    // Telegram 通知配置
    tgToken: '',             // TG_TOKEN: Telegram Bot Token
    tgId: '',                // TG_ID: Telegram Chat ID
    
    // 检测 API 配置
    checkApi: 'https://check.proxyip.cmliussss.net/check?proxyip=',  // CHECK_API: ProxyIP 检测接口
    checkApiToken: '',       // CHECK_API_TOKEN: 检测接口认证Token
    checkApiBackup: 'https://check.proxyip.cmliussss.net/check?proxyip=',      // CHECK_API_BACKUP: 备用检测接口
    checkApiBackupToken: '', // CHECK_API_BACKUP_TOKEN: 备用检测接口认证Token
    
    // DNS 配置
    dohApi: 'https://cloudflare-dns.com/dns-query',  // DOH_API: DNS over HTTPS 接口
    
    // IP 归属地查询配置
    ipInfoEnabled: false,    // IP_INFO_ENABLED: 是否启用IP归属地查询
    ipInfoApi: 'http://ip-api.com/json',  // IP_INFO_API: IP归属地查询接口
    
    // 访问控制配置
    authKey: '',             // AUTH_KEY: 面板访问密钥
    
    // 运行时配置（非环境变量）
    projectUrl: ''           // 项目URL（自动获取）
};
// ==================== 默认配置结束 ====================

const GLOBAL_SETTINGS = {
    // ── IP 检测 ──
    CONCURRENT_CHECKS: 15,       // 前端批量检测并发数
    CHECK_TIMEOUT: 3000,         // 单次 ProxyIP 检测超时(ms)

    // ── 网络超时 ──
    REMOTE_LOAD_TIMEOUT: 5000,   // 远程 URL 加载超时(ms)
    IP_INFO_TIMEOUT: 3000,       // IP 归属地查询超时(ms)
    DOH_TIMEOUT: 5000,           // DNS over HTTPS 查询超时(ms)

    // ── 数据限制 ──
    DEFAULT_MIN_ACTIVE: 3,       // 默认最小活跃 IP 数
    MAX_TRASH_SIZE: 1000,        // 垃圾桶最大条目数
    MAX_POOL_NAME_LENGTH: 50,    // IP池名称最大长度
    MAX_IPS_PER_DOMAIN: 50,      // 域名解析最多取多少个 IP
};

function safeJSONParse(str, defaultValue = null) {
    try { return str ? JSON.parse(str) : defaultValue; }
    catch { return defaultValue; }
}

const parsePoolList = raw => (raw || '').split('\n').filter(l => l.trim());

const parseTXTContent = content => content ? content.replace(/^"|"$/g, '').split(',').map(ip => ip.trim()).filter(Boolean) : [];

const extractIPKey = line => {
    if (!line) return '';
    const idx = line.indexOf('#');
    return idx >= 0 ? line.substring(0, idx).trim() : line.trim();
};

function splitComment(line) {
    if (!line) return { main: '', comment: '' };
    const idx = line.indexOf('#');
    if (idx >= 0) return { main: line.substring(0, idx).trim(), comment: line.substring(idx) };
    return { main: line.trim(), comment: '' };
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

function checkRequestAuth(request, url, env) {
    const requiredKey = (env.AUTH_KEY || '').trim();
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
        const config = createConfig(env, request);
        const url = new URL(request.url);

        const buildAuthCookie = () => `ddns_auth=${encodeURIComponent((env.AUTH_KEY || '').trim())}; Path=/; HttpOnly; Secure; SameSite=Lax`;

        // 可选鉴权：不配置 AUTH_KEY 时跳过
        const auth = checkRequestAuth(request, url, env);
        if (auth.enabled && !auth.ok && url.pathname !== '/favicon.ico') {
            return unauthorizedResponse(url);
        }

        if (url.pathname === '/') {
            const html = renderHTML(config);
            console.log(`📄 首页请求处理耗时: ${Date.now() - requestStart}ms`);
            const headers = new Headers({ 'Content-Type': 'text/html;charset=UTF-8' });
            if (auth.shouldSetCookie) {
                headers.set('Set-Cookie', buildAuthCookie());
            }
            return new Response(html, { headers });
        }

        if (url.pathname === '/favicon.ico') {
            return new Response(null, { status: 204 });
        }

        try {
            const apiStart = Date.now();
            const response = await handleAPIRequest(url, request, env, config);
            console.log(`🔧 API请求 ${url.pathname} 处理耗时: ${Date.now() - apiStart}ms`);

            // 添加性能头信息
            const headers = new Headers(response.headers);
            headers.set('X-Processing-Time', `${Date.now() - requestStart}ms`);
            if (url.pathname.startsWith('/api/') && !headers.has('Content-Type')) {
                headers.set('Content-Type', 'application/json; charset=UTF-8');
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
            const config = createConfig(env);
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
    '/api/ip-info': (url, req, env, config) => handleIPInfo(url, config),
    '/api/delete-record': (url, req, env, config) => handleDeleteRecord(url, config),
    '/api/add-a-record': (url, req, env, config) => handleAddARecord(req, config),
    '/api/maintain': (url, req, env, config) => handleMaintain(url, env, config),
    '/api/get-domain-pool-mapping': (url, req, env, config) => handleGetDomainPoolMapping(env),
    '/api/save-domain-pool-mapping': (url, req, env, config) => handleSaveDomainPoolMapping(req, env),
    '/api/create-pool': (url, req, env, config) => handleCreatePool(req, env),
    '/api/delete-pool': (url, req, env, config) => handleDeletePool(url, env),
    '/api/clear-trash': (url, req, env, config) => handleClearTrash(env),
    '/api/restore-from-trash': (url, req, env, config) => handleRestoreFromTrash(req, env)
};

const POST_ONLY_ROUTES = new Set([
    '/api/save-pool', '/api/load-remote-url', '/api/add-a-record',
    '/api/save-domain-pool-mapping', '/api/create-pool', '/api/clear-trash',
    '/api/restore-from-trash',
    '/api/delete-record',
    '/api/delete-pool', 
    '/api/maintain'
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
    const ips = await resolveDomain(domain, config);
    return jsonResponse({
        type: 'A',
        ips,
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
        const result = await checkProxyIPOnce(addr, config.checkApiBackup, config.checkApiBackupToken);
        return jsonResponse(result ?? { success: false });
    }
    const res = await checkProxyIP(target, config);
    return jsonResponse(res);
}

async function handleIPInfo(url, config) {
    const ip = url.searchParams.get('ip');
    if (!ip) {
        return badRequest({ error: '缺少IP参数' });
    }
    const info = await getIPInfo(ip, config);
    return jsonResponse(info ?? { error: '查询失败' });
}

async function handleDeleteRecord(url, config) {
    const id = url.searchParams.get('id');
    if (!id) return badRequest({ error: '缺少id参数' });
    const ip = url.searchParams.get('ip');
    const isTxt = url.searchParams.get('isTxt') === 'true';

    if (isTxt && ip) {
        // TXT记录删除单个IP
        const record = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`);
        if (!record) {
            return badRequest({ success: false, error: '获取记录失败' });
        }

        let ips = parseTXTContent(record.content);

        // 移除指定IP
        ips = ips.filter(i => i !== ip);

        if (ips.length === 0) {
            // 如果没有IP了，删除整个TXT记录
            const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
            if (result === null) {
                return jsonResponse({ success: false, error: 'CF API 删除失败' });
            }
        } else {
            // 更新TXT记录
            const newContent = `"${ips.join(',')}"`;
            const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'PUT', {
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
    
    // A记录删除
    const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
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
        const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=TXT`);

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
            const putResult = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${recordId}`, 'PUT', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
            if (putResult === null) {
                return jsonResponse({ success: false, error: 'CF API 更新TXT记录失败' });
            }
        } else {
            const postResult = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
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

    // A记录模式
    const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
        type: 'A',
        name: target.domain,
        content: ip.split(':')[0], // A记录只需要IP部分
        ttl: 60,
        proxied: false
    });

    return jsonResponse({
        success: !!result,
        colo: check.colo,
        time: check.responseTime,
        mode: 'A'
    });
}

async function handleMaintain(url, env, config) {
    const isManual = url.searchParams.get('manual') === 'true';
    const res = await maintainAllDomains(env, isManual, config);

    // 将日志包含在响应中
    return jsonResponse({
        ...res,
        // 确保所有日志都返回给前端
        allLogs: res.reports.flatMap(r => r.logs)
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

function parseDomainPort(input, defaultPort = '443') {
    if (!input) return { domain: '', port: defaultPort };
    const parts = input.trim().split(':');
    return {
        domain: parts[0],
        port: parts[1] || defaultPort
    };
}

function parseTarget(input) {
    if (!input) return null;
    
    input = input.trim();
    
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
        return { mode: 'TXT', domain, port, minActive };
    }
    
    // ALL模式
    if (input.startsWith('all@')) {
        const rest = input.substring(4);
        const { domain, port } = parseDomainPort(rest);
        return { mode: 'ALL', domain, port, minActive };
    }
    
    // A模式（默认）
    const { domain, port } = parseDomainPort(input);
    return { mode: 'A', domain, port, minActive };
}

function createConfig(env, request = null) {
    const config = { ...DEFAULT_CONFIG };

    config.apiKey = env.CF_KEY || '';
    config.zoneId = env.CF_ZONEID || '';
    config.authKey = env.AUTH_KEY || '';

    const domainsInput = env.CF_DOMAIN || '';
    if (domainsInput) {
        const parts = domainsInput.split(',').map(s => s.trim()).filter(s => s);
        config.targets = parts.map(parseTarget).filter(t => t !== null);
    }

    if (config.targets.length === 0) {
        config.targets = [{ mode: 'A', domain: '', port: '443', minActive: GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE }];
    }

    config.tgToken = env.TG_TOKEN || '';
    config.tgId = env.TG_ID || '';
    config.checkApi = env.CHECK_API || DEFAULT_CONFIG.checkApi;
    config.checkApiToken = env.CHECK_API_TOKEN || '';
    config.checkApiBackup = env.CHECK_API_BACKUP || '';
    config.checkApiBackupToken = env.CHECK_API_BACKUP_TOKEN || '';
    config.dohApi = env.DOH_API || DEFAULT_CONFIG.dohApi;
    config.ipInfoEnabled = env.IP_INFO_ENABLED === 'true';
    config.ipInfoApi = env.IP_INFO_API || DEFAULT_CONFIG.ipInfoApi;

    if (request) {
        const url = new URL(request.url);
        config.projectUrl = `${url.protocol}//${url.host}`;
    }

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

    const isValidIP = ip => ip.split('.').every(o => { const n = Number(o); return n >= 0 && n <= 255; });
    const isValidPort = p => { const n = Number(p); return n >= 1 && n <= 65535; };

    // IP:PORT 格式
    let match = mainPart.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/);
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
                        const fullFormat = `${ip}:${port}${comment}`;
                        const key = `${ip}:${port}`;
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

async function resolveDomain(domain, config) {
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=A`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.DOH_TIMEOUT)
        });
        const d = await r.json();
        return d.Answer?.filter(a => a.type === 1).map(a => a.data) ?? [];
    } catch (e) {
        console.error('❌ DNS A记录解析失败:', e);
        return [];
    }
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

async function getIPInfo(ip, config) {
    if (!config.ipInfoEnabled) return null;

    try {
        const cleanIP = ip.replace(/[\[\]]/g, '');
        const r = await fetch(
            `${config.ipInfoApi}/${cleanIP}?fields=status,country,countryCode,city,isp,as,asname&lang=zh-CN`,
            { signal: AbortSignal.timeout(GLOBAL_SETTINGS.IP_INFO_TIMEOUT) }
        );

        const data = await r.json();

        if (data.status === 'success') {
            return {
                country: data.country || '未知',
                countryCode: data.countryCode || '',
                city: data.city || '',
                isp: data.isp || '未知',
                asn: data.as || '',
                asname: data.asname || ''
            };
        }
    } catch (e) {
        console.error(`❌ IP信息查询失败 ${ip}:`, e);
    }

    return null;
}

// 批量检测IP列表，可选查询归属地
async function batchCheckIPs(ipList, checkFn, config, useBackupApi = false) {
    if (!ipList || ipList.length === 0) return [];

    // 垃圾桶复检时使用备用接口（如有）独立验证
    const effectiveCheckFn = (useBackupApi && config.checkApiBackup)
        ? (addr) => {
            const normalized = normalizeCheckAddr(addr);
            return checkProxyIPOnce(normalized, config.checkApiBackup, config.checkApiBackupToken)
                .then(r => r ?? { success: false });
        }
        : checkFn;

    const checkSettled = await Promise.allSettled(ipList.map(addr => effectiveCheckFn(addr)));
    const checkResults = checkSettled.map(r => r.status === 'fulfilled' ? r.value : { success: false });

    const ipInfoMap = new Map();
    if (config.ipInfoEnabled) {
        await Promise.allSettled(ipList.map(async (addr) => {
            const ipOnly = addr.split(':')[0];
            const info = await getIPInfo(ipOnly, config);
            if (info) ipInfoMap.set(ipOnly, info);
        }));
    }

    return checkResults.map((result, i) => ({
        address: ipList[i],
        success: result.success,
        colo: result.colo || 'N/A',
        time: result.responseTime || '-',
        ipInfo: config.ipInfoEnabled ? (ipInfoMap.get(ipList[i].split(':')[0]) || null) : null
    }));
}

async function getDomainStatus(target, config) {
    const result = {
        mode: target.mode,
        domain: target.domain,
        port: target.port,
        aRecords: [],
        txtRecords: [],
        error: null
    };

    if (target.mode === 'A' || target.mode === 'ALL') {
        const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=A`);
        if (!records) {
            result.error = CF_ERROR_MSG;
            return result;
        }
        // 使用批量检测流程
        const ipList = records.map(r => `${r.content}:${target.port}`);
        const checkResults = await batchCheckIPs(ipList, (addr) => checkProxyIP(addr, config), config);

        result.aRecords = records.map((r, i) => ({
            id: r.id,
            ip: r.content,
            port: target.port,
            success: checkResults[i].success,
            colo: checkResults[i].colo,
            time: checkResults[i].time,
            ipInfo: checkResults[i].ipInfo
        }));
    }

    if (target.mode === 'TXT' || target.mode === 'ALL') {
        const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=TXT`);
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
                success: result.success,
                colo: result.colo,
                time: result.time,
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
async function checkProxyIPOnce(addr, apiUrl, token) {
    try {
        let url = `${apiUrl}${encodeURIComponent(addr)}`;
        if (token) {
            url += `${url.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`;
        }

        const r = await fetch(url, { signal: AbortSignal.timeout(GLOBAL_SETTINGS.CHECK_TIMEOUT) });
        if (!r.ok) return null;

        const data = safeJSONParse(await r.text(), null);
        return data && typeof data === 'object' ? data : null;
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
    const result = await checkProxyIPOnce(addr, config.checkApi, config.checkApiToken);
    if (result !== null) return result;

    // 备用接口检测
    if (config.checkApiBackup) {
        const backup = await checkProxyIPOnce(addr, config.checkApiBackup, config.checkApiBackupToken);
        if (backup !== null) return backup;
    }

    return { success: false };
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

async function getCandidateIPs(env, target, addLog, poolKey) {
    const pool = await env.IP_DATA.get(poolKey) || '';
    
    if (!pool) {
        addLog(`⚠️ ${poolKey} 为空`);
        return [];
    }
    
    let candidates = parsePoolList(pool);
    
    // TXT模式不过滤端口，A模式才过滤
    if (target.mode === 'A') {
        candidates = candidates.filter(l => {
            // 提取IP:PORT部分（去除注释）
            const ipPort = extractIPKey(l);
            const parts = ipPort.split(':');
            if (parts.length >= 2) {
                return parts[1] === target.port;
            }
            return false;
        });
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
            r => ({ item, result: r }),
            () => ({ item, result: { success: false } })
        ))
    );
    const checkResults = checkSettled.map(r =>
        r.status === 'fulfilled' ? r.value : { item: currentIPs[0], result: { success: false } }
    );
    // 串行处理结果（删除操作需要顺序执行）
    for (const { item, result: checkResult } of checkResults) {
        report.checkDetails.push({
            ip: item.addr,
            status: checkResult.success ? '✅ 活跃' : '❌ 失效',
            colo: checkResult.colo || 'N/A',
            time: checkResult.responseTime || '-'
        });

        if (checkResult.success) {
            validIPs.push(item.ip);
            addLog(`  ✅ ${item.addr} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
        } else {
            report.removed.push({ ip: item.addr, reason: '检测失效' });
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
            if (checkResult && checkResult.success) {
                const ip = ipPort.split(':')[0];
                await addRecord(ip);
                validIPs.push(ip);
                report.added.push({ ip: ipPort, colo: checkResult.colo || 'N/A', time: checkResult.responseTime || '-' });
                addLog(`  ✅ ${ipPort} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
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
    addLog(`📋 维护A记录: ${target.domain}:${target.port} (最小活跃数: ${target.minActive})`);

    const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=A`);

    if (records === null) {
        addLog(`❌ 无法获取A记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }

    addLog(`当前A记录: ${records.length} 条`);

    // 使用通用维护逻辑
    await maintainRecordsCommon({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs: () => records.map(({ id, content }) => ({ id, addr: `${content}:${target.port}`, ip: content })),
        deleteRecord: async (id) => {
            const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
            if (r === null) addLog(`  ⚠️ 删除A记录失败: ${id}`);
        },
        addRecord: async (ip) => {
            const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
                type: 'A',
                name: target.domain,
                content: ip,
                ttl: 60,
                proxied: false
            });
            if (r === null) addLog(`  ⚠️ 添加A记录失败: ${ip}`);
        },
        shouldSkipCandidate: (ipPort, activeList) => {
            const [ip, port] = ipPort.split(':');
            return port !== target.port || activeList.includes(ip);
        }
    });
}

async function maintainTXTRecords(env, target, addLog, report, poolKey, checkFn, config) {
    addLog(`📝 维护TXT: ${target.domain} (最小活跃数: ${target.minActive})`);

    const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=TXT`);

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
            const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${recordId}`, 'DELETE');
            addLog(r !== null ? `📝 TXT记录已删除（所有IP失效）` : `⚠️ TXT记录删除失败`);
        } else if (newContent !== '') {
            if (recordId) {
                const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${recordId}`, 'PUT', {
                    type: 'TXT', name: target.domain, content: newContent, ttl: 60
                });
                addLog(r !== null ? `📝 TXT已更新` : `⚠️ TXT更新失败`);
            } else {
                const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
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
        if (!key) return { success: false };
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
        } else if (target.mode === 'ALL') {
            await maintainARecords(env, target, addLog, report, poolKey, checkProxyIPCached, config);

            const txtTarget = {
                ...target,
                mode: 'TXT'
            };

            const txtReport = {
                ...report,
                beforeActive: 0,
                afterActive: 0,
                added: [],
                removed: [],
                checkDetails: [],
                logs: [],
                poolRemoved: 0,
                poolExhausted: false,
                configError: false
            };
            const addTxtLog = (m) => {
                const formattedMsg = formatLogMessage(m);
                txtReport.logs.push(formattedMsg);
                console.log(formattedMsg);
            };
            await maintainTXTRecords(env, txtTarget, addTxtLog, txtReport, poolKey, checkProxyIPCached, config);
            
            report.txtLogs = txtReport.logs;
            report.txtAdded = txtReport.added;
            report.txtRemoved = txtReport.removed;
            report.txtActive = txtReport.afterActive;
            report.poolRemoved += txtReport.poolRemoved;
            if (txtReport.poolExhausted) {
                report.poolExhausted = true;
            }
            if (txtReport.configError) {
                report.configError = true;
            }
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
    if (shouldNotify) {
        tgResult = await sendTG(allReports, poolStats, isManual, config);
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

function formatIPInfoStr(ipInfoMap, ip) {
    const ipOnly = ip.split(':')[0];
    const info = ipInfoMap.get(ipOnly);
    if (!info) return '';
    let s = ` · ${info.country}`;
    if (info.asn) s += ` · ${info.asn}`;
    if (info.isp) s += ` · ${info.isp}`;
    return s;
}

function formatIPChanges(added, removed, ipInfoMap, port = '', minActive = 0, afterActive = 0) {
    let msg = '';
    if (added && added.length > 0) {
        msg += `📈 新增 ${added.length} 个IP\n`;
        added.forEach(item => {
            const displayIP = item.ip.includes(':') ? item.ip : `${item.ip}:${port}`;
            msg += `   ✅ <code>${displayIP}</code>\n`;
            msg += `      ${item.colo} · ${item.time}ms${formatIPInfoStr(ipInfoMap, item.ip)}\n`;
        });
    }
    if (removed && removed.length > 0) {
        msg += `📉 移除 ${removed.length} 个IP\n`;
        removed.forEach(item => {
            msg += `   ❌ <code>${item.ip}</code>\n`;
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

    const modeLabel = { 'A': 'A记录', 'TXT': 'TXT记录', 'ALL': '双模式' };
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

    let msg = isManual ? `🔧 <b>DDNS 手动维护报告</b>\n` : `⚙️ <b>DDNS 自动维护报告</b>\n`;
    msg += `━━━━━━━━━━━━━━━━━━\n⏰ ${timestamp}\n\n`;

    const hasConfigError = reports.some(r => r.configError);
    if (hasConfigError) {
        msg += `⚠️ <b>警告: 检测到配置错误</b>\n请检查 CF_KEY, CF_ZONEID 是否正确配置\n\n`;
    }

    // 收集所有IP用于批量查询归属地
    const allIPsForInfo = new Set();
    reports.forEach(r => {
        (r.checkDetails || []).forEach(d => allIPsForInfo.add(d.ip.split(':')[0]));
        (r.added || []).forEach(d => allIPsForInfo.add(d.ip.split(':')[0]));
        (r.txtAdded || []).forEach(d => allIPsForInfo.add(d.ip.split(':')[0]));
    });

    const ipInfoMap = new Map();
    if (config.ipInfoEnabled && allIPsForInfo.size > 0) {
        await Promise.all(Array.from(allIPsForInfo).map(async ip => {
            const info = await getIPInfo(ip, config);
            if (info) ipInfoMap.set(ip, info);
        }));
    }

    reports.forEach((report, index) => {
        if (index > 0) msg += `\n`;
        msg += `━━ <code>${report.domain}</code> ━━\n`;
        msg += `${modeLabel[report.mode]}`;
        if (report.mode === 'A' || report.mode === 'ALL') msg += ` · 端口 ${report.port}`;
        msg += ` · 最小活跃数 ${report.minActive}\n\n`;

        if (report.configError) {
            msg += `❌ <b>配置错误，无法获取记录</b>\n`;
            return;
        }

        // 检测详情
        if (report.checkDetails && report.checkDetails.length > 0) {
            report.checkDetails.forEach(d => {
                const icon = d.status.includes('✅') ? '✅' : '❌';
                msg += `${icon} <code>${d.ip}</code>\n   ${d.colo} · ${d.time}ms${formatIPInfoStr(ipInfoMap, d.ip)}\n`;
            });
            msg += `\n`;
        }

        // A记录或ALL模式的A记录部分
        if (report.mode === 'A' || report.mode === 'ALL') {
            msg += formatIPChanges(report.added, report.removed, ipInfoMap, report.port, report.minActive, report.afterActive);
        }

        // ALL模式的TXT记录部分
        if (report.mode === 'ALL' && report.txtActive !== undefined) {
            msg += `\n<b>📝 TXT记录</b>\n`;
            msg += formatIPChanges(report.txtAdded, report.txtRemoved, ipInfoMap, '', report.minActive, report.txtActive);
        }

        // 纯TXT模式
        if (report.mode === 'TXT') {
            msg += formatIPChanges(report.added, report.removed, ipInfoMap, '', report.minActive, report.afterActive);
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

function renderHTML(C) {
    const targetsJson = JSON.stringify(C.targets);
    const settingsJson = JSON.stringify(GLOBAL_SETTINGS);
    const ipInfoEnabled = C.ipInfoEnabled;
    
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro v6.9 - IP管理面板</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🌐</text></svg>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
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
        body {
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
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
        .version-badge {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 8px;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3);
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
            .version-badge {
                display: block;
                margin: 8px 0 0 0;
                width: fit-content;
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
        .result-item {
            padding: 10px 12px;
            background: #f5f5f7;
            border-radius: 10px;
            margin-bottom: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .result-item code {
            background: #fff;
            padding: 3px 6px;
            border-radius: 6px;
            font-size: 12px;
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
        .format-hint {
            font-size: 11px;
            color: var(--secondary);
            background: #fff3cd;
            padding: 8px 12px;
            border-radius: 8px;
            margin-top: 8px;
            line-height: 1.5;
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
        @media (max-width: 768px) {
            .config-info {
                font-size: 9px;
                padding: 3px 6px;
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
        
        /* TXT记录移动端优化 */
        .txt-record-item {
            display: flex;
            flex-direction: column;
            gap: 8px;
            padding: 12px;
            background: #fff;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .txt-ip-line {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .txt-ip-code {
            font-family: 'SF Mono', monospace;
            font-size: 13px;
            word-break: break-all;
            flex: 0 1 auto;
            min-width: 0;
        }
        .txt-info-group {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }
        @media (max-width: 768px) {
            .txt-record-item {
                padding: 10px;
                gap: 6px;
            }
            .txt-ip-line {
                flex-direction: column;
                align-items: flex-start;
                gap: 6px;
            }
            .txt-ip-code {
                font-size: 11px;
                width: 100%;
            }
            .txt-info-group {
                width: 100%;
                justify-content: space-between;
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
                flex-wrap: wrap !important;
                gap: 6px !important;
            }
            .filter-toolbar .form-control-sm {
                min-width: 70px !important;
                flex: 1 1 35% !important;
                font-size: 11px !important;
                padding: 6px 8px !important;
            }
            .filter-toolbar .filter-btns {
                display: flex;
                gap: 2px;
                flex-shrink: 0;
            }
            .filter-toolbar .filter-btns .btn {
                padding: 4px 6px !important;
                font-size: 12px !important;
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
        <span class="version-badge">v6.9</span>
    </h1>
    <div class="hero-actions">
        <div class="guide-toggle" onclick="toggleGuide()" title="使用步骤提示">?</div>
        <div class="config-info">
            🧭 建议流程：导入IP → 检测清洗 → 保存到池 → 执行维护
        </div>
    </div>
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
                const modeLabel = {'A': 'A记录', 'TXT': 'TXT记录', 'ALL': '双模式'};
                const label = `${t.domain} · ${modeLabel[t.mode]}${t.mode !== 'TXT' ? ' · ' + t.port : ''} · 最小${t.minActive}`;
                return `<option value="${i}">${label}</option>`;
            }).join('')}
        </select>
    </div>
</div>

<div class="container">
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
                <table class="table text-center mb-0">
                    <thead style="position:sticky;top:0;background:#fff;z-index:1">
                        <tr>
                            <th>IP地址</th>
                            <th>机房</th>
                            <th>延迟</th>
                            <th>状态</th>
                            ${ipInfoEnabled ? '<th>归属地</th>' : ''}
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
                <div class="d-flex justify-content-between align-items-center mb-3">
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
                    <div class="d-flex gap-2 align-items-center mb-2 filter-toolbar">
                        <input type="text" id="custom-port" class="form-control form-control-sm" style="min-width:80px;flex:1;border-radius:8px" placeholder="443,8443 或 443-2053" title="端口筛选：支持逗号分隔或范围格式">
                        <input type="text" id="custom-tag" class="form-control form-control-sm" style="min-width:80px;flex:1;border-radius:8px" placeholder="HK,US,JP" title="标签筛选：匹配注释中的关键词">
                        <div class="filter-btns">
                            <button class="btn btn-sm btn-outline-success" onclick="smartFilter('keep')" title="保留匹配的IP">✓</button>
                            <button class="btn btn-sm btn-outline-danger" onclick="smartFilter('exclude')" title="排除匹配的IP">✗</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="quickDeduplicate()" title="去除重复IP">⊜</button>
                        </div>
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

<script>
    const TARGETS = ${targetsJson};
    const SETTINGS = ${settingsJson};
    const IP_INFO_ENABLED = ${ipInfoEnabled};
    const AUTH_ENABLED = ${C.authKey ? 'true' : 'false'};
    let currentTargetIndex = 0;
    let currentPool = 'pool';
    let abortController = null;
    let domainPoolMapping = {};
    let availablePools = ['pool'];
    
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
            html += \`<span class="ip-info-tag">\${escapeHTML(ipInfo.asn)}</span>\`;
        }
        return html;
    }

    async function checkIPWithInfo(addr) {
        const r = await apiFetch(\`/api/check-ip?ip=\${encodeURIComponent(addr)}\`).then(r => r.json());
        let ipInfo = null;
        if (IP_INFO_ENABLED) {
            const ipOnly = addr.split(':')[0];
            ipInfo = await apiFetch(\`/api/ip-info?ip=\${encodeURIComponent(ipOnly)}\`).then(r => r.json());
            if (ipInfo && ipInfo.error) ipInfo = null;
        }
        return { ip: addr, success: r.success, colo: r.colo || 'N/A', time: r.responseTime || '-', ipInfo };
    }

    function renderIPRow(r, actionHTML) {
        return \`<tr>
            <td class="fw-bold">\${escapeHTML(r.ip)}</td>
            <td><span class="badge bg-light text-dark">\${escapeHTML(r.colo)}</span></td>
            <td>\${escapeHTML(String(r.time))}ms</td>
            <td><span class="badge \${r.success?'bg-success':'bg-danger'}">\${r.success?'✅':'❌'}</span></td>
            \${IP_INFO_ENABLED ? \`<td>\${r.ipInfo ? formatIPInfo(r.ipInfo) : '-'}</td>\` : ''}
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
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ url })
            }).then(r => r.json());
            
            if (r.success) {
                document.getElementById('ip-input').value = r.ips || '';
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
                headers: {'Content-Type': 'application/json'},
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
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ pool: content, poolKey: currentPool, mode: 'remove' })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ \${r.message}\`, 'success');
                document.getElementById('pool-count').innerText = r.count;
                document.getElementById('ip-input').value = '';
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
                                checkTargets = data.ips.map(ip => \`\${ip}:\${port}\`);
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
                        checkTargets = [normalized.split('#')[0].trim()];
                    }
                    
                    // 检测所有目标IP
                    for (const checkTarget of checkTargets) {
                        try {
                            const checkUrl = \`/api/check-ip?ip=\${encodeURIComponent(checkTarget)}\${useBackupApi ? '&useBackup=true' : ''}\`;
                            const r = await apiFetch(checkUrl, {
                                signal: signal
                            }).then(r => r.json());
                            
                            if (r.success) {
                                valid.push(checkTarget);
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
                const key = normalized.split('#')[0].trim();
                seen.set(key, normalized);
            }
        });
        
        const unique = Array.from(seen.values());
        input.value = unique.join('\\n');
        
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
        const colspan = IP_INFO_ENABLED ? '6' : '5';
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

            // A记录
            if ((data.mode === 'A' || data.mode === 'ALL') && data.aRecords && data.aRecords.length > 0) {
                data.aRecords.forEach(r => {
                    allRows.push(renderIPRow(
                        { ip: r.ip + ':' + r.port, colo: r.colo, time: r.time, success: r.success, ipInfo: r.ipInfo },
                        \`<a href="javascript:deleteRecord('\${escapeHTML(r.id)}')" class="text-danger text-decoration-none small fw-bold">🗑️</a>\`
                    ));
                });
            }

            // TXT记录（统一显示在表格中）
            if ((data.mode === 'TXT' || data.mode === 'ALL') && data.txtRecords && data.txtRecords.length > 0) {
                const record = data.txtRecords[0];
                record.ips.forEach(ip => {
                    allRows.push(renderIPRow(
                        ip,
                        \`<a href="javascript:deleteTxtIP('\${escapeHTML(record.id)}', '\${escapeHTML(ip.ip)}')" class="text-danger text-decoration-none small fw-bold">🗑️</a>\`
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
        const modeLabel = {'A': 'A记录', 'TXT': 'TXT记录', 'ALL': '双模式'};
        
        log(\`➕ 添加到\${modeLabel[target.mode]}: \${ip}\`, 'info');
        
        try {
            const r = await apiFetch('/api/add-a-record', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ip, targetIndex: currentTargetIndex })
            }).then(r => r.json());
            
            if (r.success) {
                const mode = r.mode || 'A';
                log(\`✅ 成功添加到\${mode}记录 - \${r.colo} (\${r.time}ms)\`, 'success');
                input.value = '';
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
        const colspan = IP_INFO_ENABLED ? '6' : '5';
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
                
                // 并发检测（与A记录探测统一模板）
                const checkResults = await Promise.all(data.ips.map(ip => checkIPWithInfo(ip)));

                // 显示在表格中（与A记录探测统一模板）
                t.innerHTML = checkResults.map(r => renderIPRow(r,
                    \`<button class="btn btn-sm btn-outline-primary" onclick="addToInput('\${escapeHTML(r.ip)}')" title="添加到输入框">➕</button>\`
                )).join('');
                
                const activeCount = checkResults.filter(r => r.success).length;
                log(\`📊 探测完成: \${activeCount}/\${data.ips.length} 活跃\`, activeCount === data.ips.length ? 'success' : (activeCount > 0 ? 'warn' : 'error'));
                return;
            }
            
            const isIP = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?$/.test(val);
            let targets = [];
            
            if (isIP) {
                const normalized = normalizeIPFormat(val);
                targets = [normalized ? normalized.split('#')[0].trim() : val];
            } else {
                const data = await apiFetch(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`).then(r => r.json());
                
                if (!data.ips || !Array.isArray(data.ips) || data.ips.length === 0) {
                    log(\`⚠️ 域名无A记录\`, 'warn');
                    t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">域名无A记录</td></tr>\`;
                    return;
                }
                
                targets = data.ips.map(ip => \`\${ip}:\${data.port || '443'}\`);
                log(\`📡 \${data.ips.length} 个IP (端口: \${data.port || '443'})\`, 'success');
            }
            
            // 并发检测
            const checkResults = await Promise.all(targets.map(addr => checkIPWithInfo(addr)));

            // 显示在表格中
            t.innerHTML = checkResults.map(r => renderIPRow(r,
                \`<button class="btn btn-sm btn-outline-primary" onclick="addToInput('\${escapeHTML(r.ip)}')" title="添加到输入框">➕</button>\`
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
            log(\`✅ 已添加: \${ip}\`, 'success');
        } else {
            log(\`⚠️  已存在\`, 'warn');
        }
    }
    
    async function deleteRecord(id) {
        if (!confirm('确认删除？')) return;
        
        try {
            await apiFetch(\`/api/delete-record?id=\${id}\`,{
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
            await apiFetch(\`/api/delete-record?id=\${recordId}&ip=\${encodeURIComponent(ip)}&isTxt=true\`,{
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
            
            if (r.allLogs && r.allLogs.length > 0) {
                r.allLogs.forEach(msg => log(msg, 'info', true));
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
                headers: {'Content-Type': 'application/json'},
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
            const names = { pool: '通用池', pool_trash: '垃圾桶', domain_pool_mapping: '系统数据' };
            alert(\`不能删除\${names[currentPool]}!\`);
            return;
        }
        
        if (!confirm(\`确认删除 \${currentPool}?\`)) return;
        
        try {
            await apiFetch(\`/api/delete-pool?poolKey=\${currentPool}\`,{
            method: 'POST'
        });
            
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
                headers: {'Content-Type': 'application/json'},
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
            return normalized ? normalized.split('#')[0].trim() : '';
        }).filter(k => k));
        
        const invalidLines = originalLines.filter(line => {
            const normalized = normalizeIPFormat(line);
            const key = normalized ? normalized.split('#')[0].trim() : '';
            return key && !validKeys.has(key);
        });
        
        try {
            // 1. 保存有效IP到池（覆盖）
            if (validCount > 0) {
                const r = await apiFetch('/api/save-pool', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
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
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ pool: '', poolKey: cleaningPool, mode: 'replace' })
                });
                log(\`⚠️ 洗库完成，无有效IP，池已清空\`, 'warn');
                document.getElementById('pool-count').innerText = '0';
            }
            
            // 2. 失效IP移入垃圾桶
            if (invalidLines.length > 0) {
                const trashContent = invalidLines.map(line => {
                    const normalized = normalizeIPFormat(line);
                    const key = normalized ? normalized.split('#')[0].trim() : line.split('#')[0].trim();
                    return \`\${key} # 洗库失效 \${new Date().toISOString()} 来自 \${cleaningPool}\`;
                }).join('\\n');
                
                await apiFetch('/api/save-pool', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ pool: trashContent, poolKey: 'pool_trash', mode: 'append' })
                });
                
                log(\`🗑️ 已将 \${invalidLines.length} 个失效IP移入垃圾桶\`, 'info');
            }
            
            document.getElementById('ip-input').value = '';
        } catch (e) {
            log(\`❌ 保存失败\`, 'error');
        }
    }
    
    // 垃圾桶洗库结果保存：有效IP恢复到原来的库
    async function saveTrashCleanResult(validLines, originalLines) {
        if (validLines.length === 0) {
            log(\`⚠️ 洗库完成，无有效IP可恢复\`, 'warn');
            document.getElementById('ip-input').value = '';
            return;
        }
        
        // 提取有效IP的key
        const validKeys = new Set(validLines.map(line => {
            const normalized = normalizeIPFormat(line);
            return normalized ? normalized.split('#')[0].trim() : '';
        }).filter(k => k));
        
        // 从原始行中找到对应的完整条目（包含来源信息）
        const ipsToRestore = [];
        originalLines.forEach(line => {
            const normalized = normalizeIPFormat(line);
            const key = normalized ? normalized.split('#')[0].trim() : '';
            if (key && validKeys.has(key)) {
                ipsToRestore.push(key);
            }
        });
        
        try {
            // 调用恢复API
            const r = await apiFetch('/api/restore-from-trash', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ips: ipsToRestore, restoreToSource: true })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ 垃圾桶洗库完成: \${r.message}\`, 'success');
                document.getElementById('ip-input').value = '';
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
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ips, restoreToSource: true })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ \${r.message}\`, 'success');
                loadCurrentPool();
            } else {
                log(\`❌ \${r.error}\`, 'error');
            }
        } catch (e) {
            log('❌ 恢复失败', 'error');
        }
    }
 
    function smartFilter(mode) {
        const input = document.getElementById('ip-input');
        const portFilter = document.getElementById('custom-port').value.trim();
        const tagFilter = document.getElementById('custom-tag').value.trim();
        
        if (!portFilter && !tagFilter) {
            log('❌ 请输入端口或标签筛选条件', 'error');
            return;
        }
        
        const lines = input.value.split('\\n').filter(l => l.trim());
        let filtered = lines;
        
        if (portFilter) {
            const ports = parsePortFilter(portFilter);
            if (!ports) {
                log('❌ 端口格式无效 (示例: 443,8443 或 443-2053)', 'error');
                return;
            }
            
            filtered = filtered.filter(line => {
                const normalized = normalizeIPFormat(line);
                if (!normalized) return false;
                const ipPort = normalized.split('#')[0].trim();
                const [_, linePort] = ipPort.split(':');
                const portNum = parseInt(linePort);
                
                const matchesPort = ports.some(p => {
                    if (typeof p === 'number') {
                        return portNum === p;
                    } else if (p.start && p.end) {
                        return portNum >= p.start && portNum <= p.end;
                    }
                    return false;
                });
                
                return mode === 'keep' ? matchesPort : !matchesPort;
            });
            
            const action = mode === 'keep' ? '保留' : '排除';
            log(\`📊 端口筛选: \${action} [\${portFilter}], 剩余 \${filtered.length} 个\`, 'info');
        }
        
        if (tagFilter) {
            const tags = tagFilter.split(',').map(t => t.trim()).filter(t => t);
            
            filtered = filtered.filter(line => {
                const commentIndex = line.indexOf('#');
                if (commentIndex === -1) {
                    return mode === 'exclude';
                }
                
                const comment = line.substring(commentIndex + 1).trim();
                const matchesAnyTag = tags.some(tag => comment.includes(tag));
                
                return mode === 'keep' ? matchesAnyTag : !matchesAnyTag;
            });
            
            const action = mode === 'keep' ? '保留' : '排除';
            log(\`🏷️ 标签筛选: \${action} [\${tags.join(', ')}], 剩余 \${filtered.length} 个\`, 'info');
        }
        
        input.value = filtered.join('\\n');
        log(\`✅ 筛选完成: \${lines.length} → \${filtered.length}\`, 'success');
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
        if (IP_INFO_ENABLED) {
            log('🌍 IP归属地查询: 已启用', 'info');
        }
        switchDomain();
        showPoolInfo();
        loadDomainPoolMapping();
    });
</script>
</body>
</html>`;
}