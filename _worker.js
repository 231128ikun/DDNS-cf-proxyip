/**
 * DDNS Pro & Proxy IP Manager
 */

// ==================== Editable configuration ====================
// Change these values first when tuning runtime behavior.
const APP_VERSION = '2026.05.23-11.05';
const APP_CONFIG_KEY = 'app_config';

const GLOBAL_SETTINGS = {
    // ── IP 检测 ──
    CONCURRENT_CHECKS: 32,       // 前端批量检测并发数
    CHECK_TIMEOUT: 8000,         // 单个检测接口请求超时(ms)

    // ── 网络超时 ──
    REMOTE_LOAD_TIMEOUT: 8000,   // 远程 URL 加载超时(ms)
    DOH_TIMEOUT: 5000,           // DNS over HTTPS 查询超时(ms)

    // ── 数据限制 ──
    DEFAULT_MIN_ACTIVE: 3,       // 默认最小活跃 IP 数
    MAX_TRASH_SIZE: 1000,        // 垃圾桶最大条目数
};

const SETTING_LIMITS = {
    CONCURRENT_CHECKS: { min: 1, max: 128 },
    CHECK_TIMEOUT: { min: 500, max: 30000 },
    REMOTE_LOAD_TIMEOUT: { min: 1000, max: 60000 },
    DOH_TIMEOUT: { min: 1000, max: 30000 },
    DEFAULT_MIN_ACTIVE: { min: 0, max: 100 },
    MAX_TRASH_SIZE: { min: 0, max: 100000 }
};

const CONFIG_TEXT_FIELDS = [
    { key: 'checkApi', id: 'cfg-check-api', label: '检测 API', help: '主检测接口，支持 {proxyip} 占位符。', placeholder: 'CHECK_API', span: 2 },
    { key: 'checkApiBackup', id: 'cfg-check-api-backup', label: '备用检测 API', help: '主接口失败或返回不可用时用于复检，可留空。', placeholder: 'CHECK_API_BACKUP', span: 2 },
    { key: 'dohApi', id: 'cfg-doh-api', label: 'DoH API', help: '域名解析查询接口。', placeholder: 'DOH_API' },
    { key: 'authKey', id: 'cfg-auth-key', label: '面板密钥', help: '为空则关闭前端鉴权。', placeholder: 'AUTH_KEY' },
    { key: 'tgToken', id: 'cfg-tg-token', label: 'TG Bot Token', help: '开启 TG 通知时必填。', placeholder: 'TG_TOKEN' },
    { key: 'tgId', id: 'cfg-tg-id', label: 'TG Chat ID', help: '通知接收账号或群组 ID。', placeholder: 'TG_ID' }
];

const CONFIG_NUMBER_FIELDS = [
    { key: 'CONCURRENT_CHECKS', id: 'cfg-concurrent-checks', label: '检测并发', help: '前端批量检测并发数。', placeholder: '32' },
    { key: 'CHECK_TIMEOUT', id: 'cfg-check-timeout', label: '检测超时(ms)', help: '单个检测接口请求超时。', placeholder: '3000' },
    { key: 'REMOTE_LOAD_TIMEOUT', id: 'cfg-remote-timeout', label: '远程加载超时(ms)', help: '远程 TXT URL 加载。', placeholder: '5000' },
    { key: 'DOH_TIMEOUT', id: 'cfg-doh-timeout', label: 'DoH超时(ms)', help: 'DNS over HTTPS 查询。', placeholder: '5000' },
    { key: 'DEFAULT_MIN_ACTIVE', id: 'cfg-default-min-active', label: '默认活跃数', help: '新增管理域名默认值。', placeholder: '3' },
    { key: 'MAX_TRASH_SIZE', id: 'cfg-max-trash-size', label: '垃圾桶上限', help: '超过后保留最新条目。', placeholder: '1000' }
];

const CONFIG_TOGGLE_FIELDS = [
    { key: 'scheduledEnabled', id: 'cfg-scheduled-enabled', label: '自动维护', fallback: true, env: 'SCHEDULED_ENABLED' },
    { key: 'tgEnabled', id: 'cfg-tg-enabled', label: 'TG通知', fallback: true, env: 'TG_ENABLED' }
];

const CONFIG_TEXT_KEYS = CONFIG_TEXT_FIELDS.map(({ key }) => key);

const ENV_STRING_CONFIG_FIELDS = [
    ['apiKey', 'CF_KEY'],
    ['zoneId', 'CF_ZONEID'],
    ['authKey', 'AUTH_KEY'],
    ['tgToken', 'TG_TOKEN'],
    ['tgId', 'TG_ID'],
    ['checkApi', 'CHECK_API'],
    ['checkApiBackup', 'CHECK_API_BACKUP'],
    ['dohApi', 'DOH_API']
];

// ==================== 默认配置（环境变量未设置时使用） ====================
const DEFAULT_CONFIG = {
    // 目标维护域名的Cloudflare 配置
    apiKey: '',              // CF_KEY: Cloudflare API Token
    zoneId: '',              // CF_ZONEID: Cloudflare Zone ID
    zones: [],               // app_config.zones: 多套基础域名 + CF 凭据

    // 目标维护域名的配置
    targets: [],             // app_config.targets: 配置中心保存的维护目标

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
    settings: GLOBAL_SETTINGS,

    // 运行时配置（非环境变量）
    projectUrl: ''           // 项目URL（自动获取）
};
// ==================== 默认配置结束 ====================

function normalizeRuntimeSettings(raw = {}) {
    const settings = { ...GLOBAL_SETTINGS };
    for (const [key, defaults] of Object.entries(SETTING_LIMITS)) {
        const fallback = GLOBAL_SETTINGS[key];
        const parsed = parseInt(raw?.[key] ?? fallback, 10);
        const value = Number.isFinite(parsed) ? parsed : fallback;
        settings[key] = Math.min(defaults.max, Math.max(defaults.min, value));
    }
    return settings;
}

function getRuntimeSettings(config = {}) {
    return normalizeRuntimeSettings(config.settings || GLOBAL_SETTINGS);
}

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

function parseAddr(addr, defaultPort = '443') {
    const value = extractIPKey(addr || '');
    if (!value) return { host: '', port: defaultPort, address: '' };
    // host is DNS content (bare IPv6); address is check/pool format with port.
    if (value.startsWith('[')) {
        const end = value.indexOf(']');
        const host = end >= 0 ? value.slice(1, end) : value.replace(/^\[/, '');
        const portMatch = value.match(/\]:(\d+)$/);
        const port = portMatch ? portMatch[1] : defaultPort;
        return { host, port, address: formatAddr(host, port) };
    }
    const parts = value.split(':');
    if (parts.length === 2) {
        const port = parts[1] || defaultPort;
        return { host: parts[0], port, address: `${parts[0]}:${port}` };
    }
    if (parts.length > 2) {
        return { host: value, port: defaultPort, address: formatAddr(value, defaultPort) };
    }
    return { host: value, port: defaultPort, address: `${value}:${defaultPort}` };
}

function extractHostFromAddr(addr) {
    return parseAddr(addr).host;
}

function extractPortFromAddr(addr, defaultPort = '443') {
    return parseAddr(addr, defaultPort).port;
}

function hasExplicitPort(addr) {
    const value = extractIPKey(addr || '');
    if (!value) return false;
    if (value.startsWith('[')) return /\]:(\d+)$/.test(value);
    const parts = value.split(':');
    return parts.length === 2 && parts[1] !== '';
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
    if (idx >= 0) return { main: line.substring(0, idx).trim(), comment: ` ${line.substring(idx).trim()}` };
    return { main: line.trim(), comment: '' };
}

function parsePoolEntry(line) {
    const raw = String(line || '').trim();
    if (!raw) return null;
    const beforeComment = raw.split('#')[0].trim();
    const fields = beforeComment.split(',').map(item => item.trim());
    const address = fields[0] || '';
    if (!address) return null;
    return {
        address,
        asn: fields[1] || null,
        country: fields[2] || null,
        stack: fields[3] || null
    };
}

function formatPoolAsn(asn) {
    const values = String(asn || '')
        .split(/[\/,\s]+/)
        .map(item => item.trim())
        .filter(item => item && !isUnknownMetaValue(item));
    if (!values.length) return 'null';
    return values.map(item => item.toUpperCase().startsWith('AS') ? item.toUpperCase() : `AS${item}`).join('/');
}

function formatPoolStack(stack) {
    const normalized = normalizeStackFilter(stack);
    return ['v4', 'v6', 'v4/v6'].includes(normalized) ? normalized : 'null';
}

function buildPoolEntryFromCheckResult(addr, result) {
    const parsed = parseAddr(addr);
    return [
        parsed.address || normalizeCheckAddr(addr),
        formatPoolAsn(result?.asn),
        result?.country || 'null',
        formatPoolStack(result?.stack)
    ].join(',');
}

function poolEntryNeedsMetadataRefresh(entry) {
    const meta = parsePoolEntry(entry);
    if (!meta) return false;
    return isUnknownMetaValue(meta.asn) || isUnknownMetaValue(meta.country) || isUnknownMetaValue(meta.stack);
}

function normalizeStackFilter(value) {
    const text = String(value || '').trim().toLowerCase().replace(/_/g, '-');
    if (!text) return 'v4/v6';
    if (['v4', 'ipv4', 'ipv4-only', 'only-ipv4'].includes(text)) return 'v4';
    if (['v6', 'ipv6', 'ipv6-only', 'only-ipv6'].includes(text)) return 'v6';
    if (['v4/v6', 'v6/v4', 'dual', 'dual-stack', 'both', 'all', 'ipv4-ipv6'].includes(text)) return 'v4/v6';
    return text.replace('-', '_');
}

const POOL_DEFAULT_KEY = 'ip_pool_default';
const POOL_TRASH_KEY = 'ip_pool_trash';
const POOL_NAMES_KEY = 'ip_pool_names';
const DOMAIN_POOL_MAPPING_KEY = 'domain_pool_mapping';
const NUMBERED_POOL_KEY_RE = /^ip_pool_(\d{3})$/;
function getPoolFixedName(poolKey) {
    if (poolKey === POOL_DEFAULT_KEY) return '默认池';
    if (poolKey === POOL_TRASH_KEY) return '🗑️ 垃圾桶';
    const numbered = NUMBERED_POOL_KEY_RE.exec(poolKey || '');
    if (numbered) return `池 ${numbered[1]}`;
    return String(poolKey || '');
}
function getPoolDisplayName(poolKey, poolNames = {}) {
    return poolNames?.[poolKey] || getPoolFixedName(poolKey);
}
const formatPoolNumber = value => String(value).padStart(3, '0');
const getNumberedPoolKey = value => `ip_pool_${formatPoolNumber(value)}`;
const isUserPoolKey = key => key === POOL_DEFAULT_KEY || NUMBERED_POOL_KEY_RE.test(key || '');
const isPoolDataKey = key => isUserPoolKey(key) || key === POOL_TRASH_KEY;
const isWritablePoolKey = key => isUserPoolKey(key) || key === POOL_TRASH_KEY;

function comparePoolKeys(a, b) {
    const order = key => key === POOL_DEFAULT_KEY ? 0 : (key === POOL_TRASH_KEY ? 1 : 2);
    const oa = order(a);
    const ob = order(b);
    if (oa !== ob) return oa - ob;
    const na = NUMBERED_POOL_KEY_RE.exec(a || '');
    const nb = NUMBERED_POOL_KEY_RE.exec(b || '');
    if (na && nb) return Number(na[1]) - Number(nb[1]);
    if (na) return -1;
    if (nb) return 1;
    return String(a || '').localeCompare(String(b || ''), 'zh-CN', { numeric: true });
}

async function readPoolDisplayNames(env) {
    const names = safeJSONParse(await env.IP_DATA.get(POOL_NAMES_KEY), {});
    return names && typeof names === 'object' && !Array.isArray(names) ? names : {};
}

async function writePoolDisplayNames(env, names) {
    await env.IP_DATA.put(POOL_NAMES_KEY, JSON.stringify(names || {}));
}

async function readDomainPoolMapping(env) {
    const mapping = safeJSONParse(await env.IP_DATA.get(DOMAIN_POOL_MAPPING_KEY), {});
    return mapping && typeof mapping === 'object' && !Array.isArray(mapping) ? mapping : {};
}

async function listPoolKeys(env) {
    await ensurePoolDefaults(env);
    const allKeys = await env.IP_DATA.list();
    const pools = allKeys.keys.map(k => k.name).filter(isPoolDataKey);
    if (!pools.includes(POOL_DEFAULT_KEY)) pools.unshift(POOL_DEFAULT_KEY);
    if (!pools.includes(POOL_TRASH_KEY)) pools.push(POOL_TRASH_KEY);
    return [...new Set(pools)].sort(comparePoolKeys);
}

async function ensurePoolDefaults(env) {
    if (await env.IP_DATA.get(POOL_DEFAULT_KEY) === null) await env.IP_DATA.put(POOL_DEFAULT_KEY, '');
    if (await env.IP_DATA.get(POOL_TRASH_KEY) === null) await env.IP_DATA.put(POOL_TRASH_KEY, '');
}

async function getPoolState(env) {
    await ensurePoolDefaults(env);
    const [mapping, pools, poolNames] = await Promise.all([
        readDomainPoolMapping(env),
        listPoolKeys(env),
        readPoolDisplayNames(env)
    ]);
    return { mapping, pools, poolNames };
}

function poolListToMap(pool) {
    const map = new Map();
    parsePoolList(pool).forEach(line => {
        const key = extractIPKey(line);
        if (key) map.set(key, line);
    });
    return map;
}

const formatLogMessage = msg => `[${new Date().toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' })}] ${msg}`;

const JSON_CONTENT_TYPE = 'application/json; charset=UTF-8';
const CF_ERROR_MSG = 'CF配置错误或API调用失败';

// ==================== Response helpers / Auth ====================

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
const badJsonBody = () => badRequest({ success: false, error: '请求体不是有效JSON' });

const withJsonBody = handler => async (url, request, env, config) => {
    const body = await readJsonBody(request);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return badJsonBody();
    }
    return handler(body, url, env, config, request);
};

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
    const html = renderLoginHTML(url);
    return new Response(html, { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

// ==================== Worker entry ====================

export default {
    async fetch(request, env, ctx) {
        const requestStart = Date.now();
        const url = new URL(request.url);
        const kvReady = hasKVBinding(env);
        const config = kvReady ? await createConfig(env, request) : createEnvConfig(env, request);

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

// ==================== API routes ====================

const withUrlEnv = handler => (url, request, env) => handler(url, env);
const withUrlConfig = handler => (url, request, env, config) => handler(url, config);
const withUrlEnvConfig = handler => (url, request, env, config) => handler(url, env, config);
const withEnv = handler => (url, request, env) => handler(env);
const withConfig = handler => (url, request, env, config) => handler(config);
const withJsonEnv = handler => withJsonBody((body, url, env) => handler(body, env));
const withJsonConfig = handler => withJsonBody((body, url, env, config) => handler(body, config));

const GET_API_ROUTES = {
    '/api/get-pool': withUrlEnv(handleGetPool),
    '/api/current-status': withUrlConfig(handleCurrentStatus),
    '/api/lookup-domain': withUrlConfig(handleLookupDomain),
    '/api/check-ip': withUrlConfig(handleCheckIP),
    '/api/get-domain-pool-mapping': withEnv(handleGetDomainPoolMapping),
    '/api/get-config': withConfig(handleGetConfig)
};

const POST_API_ROUTES = {
    '/api/save-pool': withJsonEnv(handleSavePool),
    '/api/load-remote-url': withJsonConfig(handleLoadRemoteUrl),
    '/api/delete-record': withUrlConfig(handleDeleteRecord),
    '/api/add-a-record': withJsonConfig(handleAddARecord),
    '/api/maintain': withUrlEnvConfig(handleMaintain),
    '/api/save-domain-pool-mapping': withJsonEnv(handleSaveDomainPoolMapping),
    '/api/create-pool': withJsonEnv(handleCreatePool),
    '/api/rename-pool': withJsonEnv(handleRenamePool),
    '/api/delete-pool': withUrlEnv(handleDeletePool),
    '/api/clear-trash': withEnv(handleClearTrash),
    '/api/restore-from-trash': withJsonEnv(handleRestoreFromTrash),
    '/api/save-config': withJsonEnv(handleSaveConfig)
};

const API_ROUTES = {
    ...GET_API_ROUTES,
    ...POST_API_ROUTES
};

// ==================== API handlers ====================

const POST_ONLY_ROUTES = new Set(Object.keys(POST_API_ROUTES));

async function handleAPIRequest(url, request, env, config) {
    if (POST_ONLY_ROUTES.has(url.pathname) && request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }
    const handler = API_ROUTES[url.pathname];
    return handler ? await handler(url, request, env, config) : new Response('Not Found', { status: 404 });
}

async function handleGetPool(url, env) {
    await ensurePoolDefaults(env);
    const poolKey = url.searchParams.get('poolKey') || POOL_DEFAULT_KEY;
    const onlyCount = url.searchParams.get('onlyCount') === 'true';
    if (!isWritablePoolKey(poolKey)) {
        return badRequest({ success: false, error: '无效的池名称' });
    }

    const pool = await env.IP_DATA.get(poolKey) || '';
    const count = pool.trim() ? pool.trim().split('\n').length : 0;

    if (onlyCount) {
        return jsonResponse({ count });
    }
    return jsonResponse({ pool, count });
}

async function handleSavePool(body, env) {
    await ensurePoolDefaults(env);
    const poolKey = body.poolKey || POOL_DEFAULT_KEY;
    const mode = body.mode || 'append'; // append: 追加, replace: 覆盖, remove: 删除
    if (!isWritablePoolKey(poolKey)) {
        return badRequest({ success: false, error: '无效的池名称' });
    }
    const newIPs = cleanIPList(body.pool || '');

    if (!newIPs && !['remove', 'replace'].includes(mode)) {
        return badRequest({ success: false, error: '没有有效IP' });
    }

    const existingMap = poolListToMap(await env.IP_DATA.get(poolKey) || '');

    const existingCount = existingMap.size;
    let responseData;

    if (mode === 'replace') {
        // 覆盖模式：清空现有，只保留新IP
        existingMap.clear();
        poolListToMap(newIPs).forEach((line, key) => existingMap.set(key, line));

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
        poolListToMap(newIPs).forEach((line, key) => existingMap.set(key, line));

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

async function handleLoadRemoteUrl(body, config) {
    const url = body.url;
    if (!url) {
        return badRequest({ success: false, error: '缺少URL' });
    }
    const ips = await loadFromRemoteUrl(url, config);
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
        const record = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`);
        if (!record) return badRequest({ success: false, error: '获取记录失败' });

        const remaining = parseTXTContent(record.content).filter(item => item !== ip);
        const ok = remaining.length === 0
            ? await deleteDNSRecord(cfConfig, id)
            : await upsertTXTRecord(cfConfig, record.name, id, remaining);
        return ok
            ? jsonResponse({ success: true })
            : jsonResponse({ success: false, error: 'CF API 更新失败' });
    }

    return await deleteDNSRecord(cfConfig, id)
        ? jsonResponse({ success: true })
        : jsonResponse({ success: false, error: 'CF API 删除失败' });
}

async function handleAddARecord(body, config) {
    const ip = body.ip;
    const targetIndex = body.targetIndex || 0;
    const target = config.targets[targetIndex];
    const cfConfig = getTargetCFConfig(config, target);

    if (!ip || !target) {
        return badRequest({ success: false, error: '参数错误' });
    }

    const addr = target.mode === 'TXT' ? normalizeCheckAddr(ip) : parseAddr(ip, target.port).address;

    // TXT模式：追加到TXT记录
    if (target.mode === 'TXT') {
        const records = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=TXT`);
        if (records === null) {
            return jsonResponse({ success: false, error: CF_ERROR_MSG });
        }

        const record = records?.[0] || null;
        const currentIPs = record ? parseTXTContent(record.content) : [];
        if (currentIPs.includes(addr)) {
            return jsonResponse({ success: false, error: 'IP已存在于TXT记录' });
        }

        currentIPs.push(addr);
        if (!await upsertTXTRecord(cfConfig, target.domain, record?.id, currentIPs)) {
            return jsonResponse({ success: false, error: 'CF API 保存TXT记录失败' });
        }

        return jsonResponse({
            success: true,
            mode: 'TXT'
        });
    }

    // 地址记录模式
    const added = await addAddressRecord(cfConfig, target.domain, extractHostFromAddr(addr));

    return jsonResponse({
        success: added.ok,
        mode: added.type
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
    return jsonResponse(await getPoolState(env));
}

async function handleSaveDomainPoolMapping(body, env) {
    await ensurePoolDefaults(env);
    const mapping = body.mapping && typeof body.mapping === 'object' && !Array.isArray(body.mapping)
        ? Object.fromEntries(Object.entries(body.mapping)
            .filter(([, poolKey]) => isUserPoolKey(poolKey)))
        : {};
    await env.IP_DATA.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(mapping));
    return jsonResponse({ success: true, ...(await getPoolState(env)) });
}

async function handleCreatePool(body, env) {
    await ensurePoolDefaults(env);
    const displayName = String(body.displayName || '').trim();

    if (!displayName) {
        return badRequest({ success: false, error: '请输入池显示名称' });
    }

    const pools = await listPoolKeys(env);
    let nextIndex = 1;
    for (const key of pools) {
        const match = NUMBERED_POOL_KEY_RE.exec(key);
        if (match) nextIndex = Math.max(nextIndex, Number(match[1]) + 1);
    }

    let poolKey = getNumberedPoolKey(nextIndex);
    while (await env.IP_DATA.get(poolKey) !== null) {
        nextIndex++;
        poolKey = getNumberedPoolKey(nextIndex);
    }

    await env.IP_DATA.put(poolKey, '');
    const poolNames = await readPoolDisplayNames(env);
    poolNames[poolKey] = displayName;
    await writePoolDisplayNames(env, poolNames);
    return jsonResponse({ success: true, poolKey, displayName, ...(await getPoolState(env)) });
}

async function handleRenamePool(body, env) {
    await ensurePoolDefaults(env);
    const poolKey = body.poolKey || POOL_DEFAULT_KEY;
    const displayName = String(body.displayName || '').trim();
    if (!isUserPoolKey(poolKey)) {
        return badRequest({ success: false, error: '池名称无效' });
    }
    if (!displayName) {
        return badRequest({ success: false, error: '显示名称不能为空' });
    }

    const pool = await env.IP_DATA.get(poolKey);
    if (pool === null && poolKey !== POOL_DEFAULT_KEY) {
        return badRequest({ success: false, error: '池不存在' });
    }

    const poolNames = await readPoolDisplayNames(env);
    const defaultName = getPoolFixedName(poolKey);
    if (displayName === defaultName) {
        delete poolNames[poolKey];
    } else {
        poolNames[poolKey] = displayName;
    }
    await writePoolDisplayNames(env, poolNames);
    return jsonResponse({ success: true, poolKey, displayName, ...(await getPoolState(env)) });
}

async function handleDeletePool(url, env) {
    await ensurePoolDefaults(env);
    const poolKey = url.searchParams.get('poolKey') || '';

    if (!poolKey) {
        return badRequest({ success: false, error: '缺少poolKey参数' });
    }

    if (poolKey === POOL_DEFAULT_KEY || poolKey === POOL_TRASH_KEY || !isUserPoolKey(poolKey)) {
        return badRequest({ success: false, error: `不能删除${getPoolFixedName(poolKey)}` });
    }

    const existing = await env.IP_DATA.get(poolKey);
    if (existing === null) {
        return badRequest({ success: false, error: '池不存在' });
    }

    try {
        await env.IP_DATA.delete(poolKey);
        const poolNames = await readPoolDisplayNames(env);
        delete poolNames[poolKey];
        await writePoolDisplayNames(env, poolNames);
        const mapping = await readDomainPoolMapping(env);
        let mappingChanged = false;
        for (const [domain, boundPool] of Object.entries(mapping)) {
            if (boundPool === poolKey) {
                mapping[domain] = POOL_DEFAULT_KEY;
                mappingChanged = true;
            }
        }
        if (mappingChanged) await env.IP_DATA.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(mapping));
        return jsonResponse({ success: true, ...(await getPoolState(env)) });
    } catch (e) {
        console.error('删除池失败:', e);
        return jsonResponse({ success: false, error: '删除池失败' });
    }
}

async function handleClearTrash(env) {
    await ensurePoolDefaults(env);
    await env.IP_DATA.put(POOL_TRASH_KEY, '');
    return jsonResponse({ success: true, message: '垃圾桶已清空' });
}

async function handleRestoreFromTrash(body, env) {
    await ensurePoolDefaults(env);
    const ipsToRestore = body.ips || [];
    const restoreToSource = body.restoreToSource === true;
    const targetPool = body.targetPool || POOL_DEFAULT_KEY;
    if (!Array.isArray(ipsToRestore)) {
        return badRequest({ success: false, error: 'ips 必须是数组' });
    }
    if (!isUserPoolKey(targetPool)) {
        return badRequest({ success: false, error: '无效的目标池' });
    }

    if (ipsToRestore.length === 0) {
        return badRequest({ success: false, error: '没有选择IP' });
    }

    // 获取垃圾桶
    let trashList = parsePoolList(await env.IP_DATA.get(POOL_TRASH_KEY));

    let restored = 0;
    const restoredByPool = {};
    const poolNames = await readPoolDisplayNames(env);

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
        // 例如：`1.2.3.4:443 # 洗库失效 2024-01-01T00:00:00.000Z 来自 ip_pool_001`
        const idx = trashEntry.lastIndexOf(' 来自 ');
        if (idx !== -1) {
            const sourcePool = trashEntry.slice(idx + 4).trim();
            // 直接返回来源池名（如 ip_pool_001），不需要通过域名映射
            if (isPoolDataKey(sourcePool)) {
                return sourcePool;
            }
        }
        return POOL_DEFAULT_KEY;
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
            const poolEntry = parsePoolEntry(trashEntry);
            const restoredEntry = poolEntry
                ? [poolEntry.address, poolEntry.asn || 'null', poolEntry.country || 'null', formatPoolStack(poolEntry.stack)].join(',')
                : (parseIPLine(trashEntry) || ip);
            const restoredKey = extractIPKey(restoredEntry);

            // 添加到目标池（如果不存在）- 保留 IP 池元数据，不携带垃圾桶注释
            if (restoredKey && !poolObj.set.has(restoredKey)) {
                poolObj.list.push(restoredEntry);
                poolObj.set.add(restoredKey);
                restored++;
                restoredByPool[toPool] = (restoredByPool[toPool] || 0) + 1;
            }
        }
    }

    // 保存
    await env.IP_DATA.put(POOL_TRASH_KEY, Array.from(trashMap.values()).join('\n'));
    for (const [poolKey, poolObj] of poolCache.entries()) {
        await env.IP_DATA.put(poolKey, poolObj.list.join('\n'));
    }

    const rawRestoreDisplay = Object.entries(restoredByPool).map(([poolKey, count]) => ({
        poolKey,
        name: getPoolDisplayName(poolKey, poolNames),
        count
    }));
    const restoreNameCounts = rawRestoreDisplay.reduce((acc, item) => {
        acc[item.name] = (acc[item.name] || 0) + 1;
        return acc;
    }, {});
    const restoredByPoolDisplay = rawRestoreDisplay.map(item => ({
        ...item,
        label: restoreNameCounts[item.name] > 1 ? `${item.name}（${getPoolFixedName(item.poolKey)}）` : item.name
    }));
    const restoreTargetName = getPoolDisplayName(targetPool, poolNames);
    const restoreSummary = restoredByPoolDisplay
        .map(item => `${item.label} ${item.count} 个`)
        .join('，');

    return jsonResponse({
        success: true,
        restored,
        restoredByPool,
        restoredByPoolDisplay,
        message: restoreToSource
            ? `已恢复 ${restored} 个IP到源IP库${restoreSummary ? `（${restoreSummary}）` : ''}`
            : `已恢复 ${restored} 个IP到 ${restoreTargetName}`
    });
}

function getEditableConfig(config) {
    return {
        apiKey: config.apiKey || '',
        zoneId: config.zoneId || '',
        zones: config.zones || [],
        targets: config.targets || [],
        ...Object.fromEntries(CONFIG_TEXT_KEYS.map(key => [key, config[key] || ''])),
        ...Object.fromEntries(CONFIG_TOGGLE_FIELDS.map(({ key }) => [key, config[key] !== false])),
        settings: getRuntimeSettings(config)
    };
}

// ==================== Config parsing / normalization ====================

async function handleGetConfig(config) {
    return jsonResponse({ success: true, config: getEditableConfig(config) });
}

async function handleSaveConfig(body, env) {
    const rawConfig = body.config && typeof body.config === 'object' ? body.config : body;
    const normalized = normalizeSavedConfig(rawConfig);
    const duplicateError = getConfigDuplicateError(normalized);
    if (duplicateError) {
        return badRequest({ success: false, error: duplicateError });
    }
    await env.IP_DATA.put(APP_CONFIG_KEY, JSON.stringify(normalized));
    return jsonResponse({ success: true, config: normalized });
}

function normalizeConfigCompareValue(value) {
    return String(value || '').trim().toLowerCase();
}

function findDuplicateConfigValue(items, keyFn) {
    const seen = new Set();
    for (const item of items || []) {
        const key = normalizeConfigCompareValue(keyFn(item));
        if (!key) continue;
        if (seen.has(key)) return key;
        seen.add(key);
    }
    return '';
}

function getTargetDuplicateKey(target = {}) {
    const domain = normalizeConfigCompareValue(target.domain);
    const mode = normalizeTargetMode(target.mode);
    return domain ? `${domain}|${mode}` : '';
}

function getConfigDuplicateError(config = {}) {
    const duplicateBaseDomain = findDuplicateConfigValue(config.zones, zone => zone.baseDomain);
    if (duplicateBaseDomain) {
        return `权限配置存在重复目标维护域名：${duplicateBaseDomain}`;
    }

    const duplicateTarget = findDuplicateConfigValue(config.targets, getTargetDuplicateKey);
    if (duplicateTarget) {
        const [domain, mode] = duplicateTarget.split('|');
        return `管理域名存在重复项：${domain} / ${mode === 'TXT' ? 'TXT' : 'A/AAAA'}`;
    }

    return '';
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


function normalizeTargetConfig(target, settings = GLOBAL_SETTINGS) {
    if (!target || typeof target !== 'object') return null;
    const baseDomain = String(target.baseDomain || '').trim();
    const prefix = String(target.prefix || '').trim().replace(/^\.+|\.+$/g, '');
    const domain = String(target.domain || buildManagedDomain(prefix, baseDomain)).trim();
    if (!domain) return null;
    const mode = normalizeTargetMode(target.mode);
    const port = mode === 'TXT' ? 'any' : (String(target.port || '443').trim() || '443');
    const normalizedSettings = normalizeRuntimeSettings(settings);
    const parsedMinActive = parseInt(target.minActive ?? normalizedSettings.DEFAULT_MIN_ACTIVE, 10);
    const minActive = Math.max(0, Number.isFinite(parsedMinActive) ? parsedMinActive : normalizedSettings.DEFAULT_MIN_ACTIVE);
    const exitFilter = normalizeExitFilter(target.exitFilter);
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




function normalizeZoneConfig(zone) {
    if (!zone || typeof zone !== 'object') return null;
    const baseDomain = String(zone.baseDomain || zone.domain || '').trim().replace(/^\.+|\.+$/g, '');
    const zoneId = String(zone.zoneId || '').trim();
    const apiKey = String(zone.apiKey || '').trim();
    const label = String(zone.label || zone.name || baseDomain || zoneId || '未命名').trim();
    if (!baseDomain && !zoneId && !apiKey) return null;
    return { name: label, baseDomain, zoneId, apiKey, label };
}



function normalizeSavedConfig(rawConfig = {}) {
    const settings = normalizeRuntimeSettings(rawConfig.settings || rawConfig);
    const zones = Array.isArray(rawConfig.zones)
        ? rawConfig.zones.map(normalizeZoneConfig).filter(Boolean)
        : [];
    const targets = Array.isArray(rawConfig.targets)
        ? rawConfig.targets.map(target => normalizeTargetConfig(target, settings)).filter(Boolean)
        : [];
    return {
        apiKey: String(rawConfig.apiKey || '').trim(),
        zoneId: String(rawConfig.zoneId || '').trim(),
        zones,
        targets,
        ...Object.fromEntries(CONFIG_TEXT_KEYS.map(key => [key, String(rawConfig[key] || '').trim()])),
        ...Object.fromEntries(CONFIG_TOGGLE_FIELDS.map(({ key, fallback }) => [key, parseBooleanConfig(rawConfig[key], fallback)])),
        settings
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

function createEnvConfig(env = {}, request = null) {
    const config = { ...DEFAULT_CONFIG };
    config.settings = normalizeRuntimeSettings();

    ENV_STRING_CONFIG_FIELDS.forEach(([key, envKey]) => {
        config[key] = env[envKey] || DEFAULT_CONFIG[key];
    });
    const envBaseDomain = String(env.CF_BASE_DOMAIN || '').trim();
    config.zones = (config.apiKey || config.zoneId || envBaseDomain)
        ? [{ baseDomain: envBaseDomain, zoneId: config.zoneId, apiKey: config.apiKey, label: envBaseDomain || '环境变量配置' }]
        : [];
    CONFIG_TOGGLE_FIELDS.forEach(({ key, env: envKey }) => {
        config[key] = parseBooleanConfig(env[envKey], DEFAULT_CONFIG[key]);
    });
    if (request) {
        const url = new URL(request.url);
        config.projectUrl = `${url.protocol}//${url.host}`;
    }
    return config;
}

async function createConfig(env, request = null) {
    const config = createEnvConfig(env, request);

    const savedConfig = await loadSavedConfig(env);
    if (savedConfig) {
        for (const key of ['apiKey', 'zoneId', ...CONFIG_TEXT_KEYS]) {
            if (savedConfig[key]) config[key] = savedConfig[key];
        }
        if (savedConfig.zones.length > 0) {
            config.zones = savedConfig.zones;
            config.apiKey = savedConfig.zones[0].apiKey || config.apiKey;
            config.zoneId = savedConfig.zones[0].zoneId || config.zoneId;
        }
        CONFIG_TOGGLE_FIELDS.forEach(({ key }) => {
            config[key] = savedConfig[key];
        });
        config.settings = savedConfig.settings;
        if (savedConfig.targets.length > 0) {
            config.targets = savedConfig.targets;
        }
    }

    return Object.freeze(config);
}

async function batchAddToTrash(env, entries, config = {}) {
    if (!entries || entries.length === 0) return;
    const trashKey = POOL_TRASH_KEY;
    let trashList = parsePoolList(await env.IP_DATA.get(trashKey));
    const trashIPSet = new Set(trashList.map(t => extractIPKey(t)));
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

    for (const { ipAddr, reason, poolKey } of entries) {
        const ipKey = extractIPKey(ipAddr);
        if (ipKey && !trashIPSet.has(ipKey)) {
            const poolEntry = parsePoolEntry(ipAddr);
            const cleanEntry = poolEntry
                ? [poolEntry.address, poolEntry.asn || 'null', poolEntry.country || 'null', formatPoolStack(poolEntry.stack)].join(',')
                : ipAddr;
            const trashEntry = `${cleanEntry} # ${reason} ${timestamp}${poolKey ? ' 来自 ' + poolKey : ''}`;
            trashList.push(trashEntry);
            trashIPSet.add(ipKey);
        }
    }

    const maxTrashSize = getRuntimeSettings(config).MAX_TRASH_SIZE;
    if (trashList.length > maxTrashSize) {
        trashList = maxTrashSize > 0 ? trashList.slice(-maxTrashSize) : [];
    }

    await env.IP_DATA.put(trashKey, trashList.join('\n'));
}

// ==================== IP parsing / DNS lookup ====================

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

function cleanIPList(text) {
    if (!text) return '';
    const map = new Map();
    const lines = text.split('\n');

    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;

        const parsed = parseIPLine(line);
        if (parsed) {
            const key = extractIPKey(parsed);
            map.set(key, parsed);
        }
    }

    return Array.from(map.values()).join('\n');
}

async function loadFromRemoteUrl(url, config = {}) {
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
            signal: AbortSignal.timeout(getRuntimeSettings(config).REMOTE_LOAD_TIMEOUT)
        });
        if (r.ok) {
            const text = await r.text();
            return cleanIPList(text);
        }
    } catch (e) {
        console.error(`❌ 远程加载失败 ${url}:`, e);
    }
    return '';
}

async function dohQuery(domain, type, config) {
    const settings = getRuntimeSettings(config);
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(settings.DOH_TIMEOUT)
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

async function resolveTXTRecord(domain, config) {
    const settings = getRuntimeSettings(config);
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=TXT`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(settings.DOH_TIMEOUT)
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

// ==================== Proxy check normalization ====================

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

function isUnknownMetaValue(value) {
    const text = String(value ?? '').trim().toLowerCase();
    return !text || text === 'null' || text === 'unknown' || text === 'n/a' || text === '-' || text === 'asnull' || text === 'asunknown';
}

function targetMetaMatchesStoredEntry(entry, target) {
    const meta = parsePoolEntry(entry);
    if (!meta) return true;
    if (target.country && !isUnknownMetaValue(meta.country)) {
        const countries = String(meta.country || '').toUpperCase().split(/[\/,\s]+/).filter(Boolean);
        if (!countries.includes(String(target.country).toUpperCase())) return false;
    }
    if (target.asn && !isUnknownMetaValue(meta.asn)) {
        const asns = String(meta.asn || '').replace(/AS/gi, '').split(/[\/,\s]+/).filter(Boolean);
        if (!asns.includes(String(target.asn).replace(/^AS/i, ''))) return false;
    }
    if (normalizeExitFilter(target.exitFilter) !== 'any' && !isUnknownMetaValue(meta.stack)) {
        if (!exitFilterMatchesResult({ stack: meta.stack }, target.exitFilter)) return false;
    }
    return true;
}

function buildCheckApiUrl(apiUrl, addr) {
    const encoded = encodeURIComponent(addr);
    if (apiUrl.includes('{proxyip}')) return apiUrl.replaceAll('{proxyip}', encoded);
    return `${apiUrl}${encoded}`;
}

// 批量调用检测接口，并统一整理 API 返回的出口、ASN、国家信息
async function batchCheckIPs(ipList, checkFn, config) {
    if (!ipList || ipList.length === 0) return [];

    const effectiveCheckFn = checkFn;

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
        // 批量检测当前地址记录
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

            // 批量检测 TXT 中的地址
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

function normalizeCheckAddr(input) {
    return parseAddr(input || '').address;
}

async function checkProxyIP(input, config) {
    const addr = normalizeCheckAddr(input);
    const timeout = getRuntimeSettings(config).CHECK_TIMEOUT;
    const apis = [config.checkApi, config.checkApiBackup].map(api => String(api || '').trim()).filter(Boolean);
    let lastResult = null;

    for (const apiUrl of apis) {
        try {
            const r = await fetch(buildCheckApiUrl(apiUrl, addr), { signal: AbortSignal.timeout(timeout) });
            if (!r.ok) continue;

            const data = safeJSONParse(await r.text(), null);
            const result = data && typeof data === 'object' ? normalizeCheckResult(data, addr) : null;
            if (!result) continue;

            lastResult = result;
            if (result.success) return result;
        } catch {
            // 当前接口失败，继续尝试下一个检测接口。
        }
    }

    return lastResult ?? normalizeCheckResult({ success: false }, addr);
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

// ==================== Maintenance workflow ====================

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

async function deleteDNSRecord(cfConfig, id) {
    return await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${id}`, 'DELETE') !== null;
}

async function upsertTXTRecord(cfConfig, domain, recordId, ips) {
    const content = `"${ips.join(',')}"`;
    if (recordId) {
        return await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records/${recordId}`, 'PUT', {
            type: 'TXT',
            name: domain,
            content,
            ttl: 60
        }) !== null;
    }
    return await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records`, 'POST', {
        type: 'TXT',
        name: domain,
        content,
        ttl: 60
    }) !== null;
}

async function addAddressRecord(cfConfig, domain, ip) {
    const content = String(ip || '').replace(/^\[/, '').replace(/\]$/, '');
    const recordType = getDNSRecordTypeForIP(content);
    const result = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records`, 'POST', {
        type: recordType,
        name: domain,
        content,
        ttl: 60,
        proxied: false
    });
    return { ok: result !== null, type: recordType };
}

async function getCandidateIPs(env, target, addLog, poolKey) {
    const pool = await env.IP_DATA.get(poolKey) || '';
    const poolName = getPoolFixedName(poolKey);

    if (!pool) {
        addLog(`⚠️ ${poolName} 为空`);
        return [];
    }

    let candidates = parsePoolList(pool);

    // TXT模式不过滤端口，地址记录模式才过滤
    if (target.mode === 'A') {
        candidates = candidates.filter(l => {
            const ipPort = extractIPKey(l);
            return extractPortFromAddr(ipPort) === target.port && targetMetaMatchesStoredEntry(l, target);
        });
    } else {
        candidates = candidates.filter(l => targetMetaMatchesStoredEntry(l, target));
    }

    addLog(`📦 使用 ${poolName}: ${candidates.length} 个候选IP`);
    return candidates;
}

async function checkCurrentItems(currentItems, checkFn) {
    const settled = await Promise.allSettled(
        currentItems.map(item => checkFn(item.addr).then(
            result => ({ item, result: normalizeCheckResult(result, item.addr) }),
            () => ({ item, result: normalizeCheckResult({ success: false }, item.addr) })
        ))
    );
    return settled
        .map(r => r.status === 'fulfilled' ? r.value : null)
        .filter(Boolean);
}

function appendCheckDetail(report, item, result) {
    report.checkDetails.push({
        ip: item.addr,
        status: result.success ? '✅ 活跃' : '❌ 失效',
        colo: result.colo || 'N/A',
        time: result.responseTime || '-',
        country: result.country || 'null',
        asn: result.asn || 'null'
    });
}

function removePoolEntry(poolList, ipAddr) {
    const before = poolList.length;
    const entry = poolList.find(p => extractIPKey(p) === ipAddr) || '';
    const next = poolList.filter(p => extractIPKey(p) !== ipAddr);
    return { list: next, removed: before !== next.length, entry };
}

async function savePoolAndTrash(env, poolKey, poolList, poolModified, trashBatch, config = {}) {
    if (trashBatch.length > 0) await batchAddToTrash(env, trashBatch, config);
    if (poolModified) await env.IP_DATA.put(poolKey, poolList.join('\n'));
}

function sameAddressSet(a, b) {
    if (a.length !== b.length) return false;
    const set = new Set(a);
    return b.every(item => set.has(item));
}

function getTargetFilterSummary(target) {
    return [target.country ? `国家:${target.country}` : '', target.asn ? `ASN:${target.asn}` : ''].filter(Boolean).join(', ') || '无';
}

function checkResultMatchesTarget(result, target) {
    return result.success && exitFilterMatchesResult(result, target.exitFilter) && targetMetaMatchesResult(result, target);
}

function appendMaintenanceIPReport(list, ip, result, extra = {}) {
    list.push({
        ip,
        ...extra,
        colo: result.colo || 'N/A',
        time: result.responseTime || '-',
        country: result.country || 'null',
        asn: result.asn || 'null'
    });
}

function refreshPoolEntryMetadata(poolList, item, ipPort, result) {
    if (!(result.success && poolEntryNeedsMetadataRefresh(item))) {
        return { poolList, modified: false };
    }
    const refreshed = buildPoolEntryFromCheckResult(ipPort, result);
    return {
        poolList: poolList.map(line => extractIPKey(line) === ipPort ? refreshed : line),
        modified: true
    };
}

async function runMaintenanceCore({
    env,
    target,
    addLog,
    report,
    poolKey,
    checkFn,
    currentItems,
    getCurrentActiveValue,
    onRemoveCurrent = null,
    formatCurrentRemovedLog,
    buildCandidate,
    addCandidate = null
}) {
    let poolList = parsePoolList(await env.IP_DATA.get(poolKey));
    let poolModified = false;
    const trashBatch = [];
    const activeItems = [];
    report.poolKeyUsed = poolKey;

    for (const { item, result } of await checkCurrentItems(currentItems, checkFn)) {
        appendCheckDetail(report, item, result);
        if (checkResultMatchesTarget(result, target)) {
            activeItems.push(getCurrentActiveValue(item, result));
            addLog(`  ✅ ${item.addr} - ${result.colo} (${result.responseTime}ms)`);
            continue;
        }

        const reason = result.success ? '出口/国家/ASN不匹配' : '检测失效';
        appendMaintenanceIPReport(report.removed, item.addr, result, { reason });
        if (onRemoveCurrent) await onRemoveCurrent(item, result);

        const removed = removePoolEntry(poolList, item.addr);
        poolList = removed.list;
        if (removed.removed) {
            report.poolRemoved++;
            poolModified = true;
        }
        trashBatch.push({ ipAddr: removed.entry || item.addr, reason: result.success ? '出口/国家/ASN不匹配' : '维护失效', poolKey });
        addLog(formatCurrentRemovedLog
            ? formatCurrentRemovedLog(item, result)
            : (result.success ? `  ❌ ${item.addr} - 出口/国家/ASN不匹配，已移除` : `  ❌ ${item.addr} - 失效已移除，已放入垃圾桶`));
    }

    report.beforeActive = activeItems.length;

    if (activeItems.length < target.minActive) {
        addLog(`需补充: ${target.minActive - activeItems.length} 个`);
        const candidates = await getCandidateIPs(env, target, addLog, poolKey);

        for (const item of candidates) {
            if (activeItems.length >= target.minActive) break;

            const candidate = buildCandidate(item, activeItems);
            if (!candidate) continue;

            const result = normalizeCheckResult(await checkFn(candidate.addr), candidate.addr);
            if (!checkResultMatchesTarget(result, target)) {
                if (result.success) {
                    const refreshed = refreshPoolEntryMetadata(poolList, item, candidate.addr, result);
                    poolList = refreshed.poolList;
                    poolModified = poolModified || refreshed.modified;
                    addLog(`  ⏭️ ${candidate.addr} - 出口/国家/ASN不匹配`);
                } else {
                    const removed = removePoolEntry(poolList, candidate.addr);
                    poolList = removed.list;
                    if (removed.removed) {
                        report.poolRemoved++;
                        poolModified = true;
                    }
                    trashBatch.push({ ipAddr: removed.entry || candidate.addr, reason: '补充检测失败', poolKey });
                    addLog(`  ❌ ${candidate.addr} - 检测失败，从池中移除并放入垃圾桶`);
                }
                continue;
            }

            const addResult = addCandidate ? await addCandidate(candidate, result) : { ok: true, activeValue: candidate.activeValue };
            if (!addResult?.ok) {
                if (addResult?.log) addLog(addResult.log);
                continue;
            }

            activeItems.push(addResult.activeValue ?? candidate.activeValue ?? candidate.addr);
            appendMaintenanceIPReport(report.added, candidate.addr, result);

            const refreshed = refreshPoolEntryMetadata(poolList, item, candidate.addr, result);
            poolList = refreshed.poolList;
            poolModified = poolModified || refreshed.modified;
            addLog(`  ✅ ${candidate.addr} - ${result.colo} (${result.responseTime}ms)`);
        }

        if (activeItems.length < target.minActive) {
            report.poolExhausted = true;
            addLog(`⚠️ ${getPoolFixedName(poolKey)} 库存不足，无法达到最小活跃数 ${target.minActive}`);
        }
    }

    return { activeItems, poolList, poolModified, trashBatch };
}

async function finalizeMaintenanceCore(env, poolKey, report, state, config) {
    await savePoolAndTrash(env, poolKey, state.poolList, state.poolModified, state.trashBatch, config);
    report.poolAfterCount = state.poolList.length;
    report.afterActive = state.activeItems.length;
}

async function maintainARecords(env, target, addLog, report, poolKey, checkFn, config) {
    addLog(`📋 维护地址记录(A/AAAA): ${target.domain}:${target.port} (最小活跃数: ${target.minActive}, 筛选: ${getTargetFilterSummary(target)})`);
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

    const currentItems = records.map(({ id, content, type }) => ({
        id,
        type,
        addr: formatAddr(content, target.port),
        host: content
    }));

    const state = await runMaintenanceCore({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        currentItems,
        getCurrentActiveValue: item => item.host,
        onRemoveCurrent: item => deleteDNSRecord(cfConfig, item.id),
        formatCurrentRemovedLog: (item, result) => result.success
            ? `  ❌ ${item.addr} - 出口/国家/ASN不匹配，已删除`
            : `  ❌ ${item.addr} - 失效已删除，已放入垃圾桶`,
        buildCandidate: (item, activeItems) => {
            const ipPort = extractIPKey(item);
            const parsed = parseAddr(ipPort, target.port);
            if (!ipPort || parsed.port !== target.port || activeItems.includes(parsed.host)) return null;
            return { addr: ipPort, activeValue: parsed.host, host: parsed.host };
        },
        addCandidate: async candidate => {
            const added = await addAddressRecord(cfConfig, target.domain, candidate.host);
            return added.ok
                ? { ok: true, activeValue: candidate.host }
                : { ok: false, log: `  ⚠️ 添加${added.type}记录失败: ${candidate.host}` };
        }
    });

    await finalizeMaintenanceCore(env, poolKey, report, state, config);
}

async function maintainTXTRecords(env, target, addLog, report, poolKey, checkFn, config) {
    addLog(`📝 维护TXT: ${target.domain} (最小活跃数: ${target.minActive}, 筛选: ${getTargetFilterSummary(target)})`);
    const cfConfig = getTargetCFConfig(config, target);

    const records = await fetchCF(cfConfig, `/zones/${cfConfig.zoneId}/dns_records?name=${target.domain}&type=TXT`);
    if (records === null) {
        addLog(`❌ 无法获取TXT记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }

    const record = records?.[0] || null;
    const originalIPs = record ? parseTXTContent(record.content) : [];
    addLog(`当前TXT: ${originalIPs.length} 个IP`);

    const currentItems = originalIPs.map(addr => ({ addr, ip: addr }));
    const state = await runMaintenanceCore({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        currentItems,
        getCurrentActiveValue: item => item.addr,
        formatCurrentRemovedLog: (item, result) => result.success
            ? `  ❌ ${item.addr} - 出口/国家/ASN不匹配，已从TXT移除`
            : `  ❌ ${item.addr} - 失效，已从TXT移除并放入垃圾桶`,
        buildCandidate: (item, activeItems) => {
            const ipPort = extractIPKey(item);
            if (!ipPort || activeItems.includes(ipPort)) return null;
            return { addr: ipPort, activeValue: ipPort };
        }
    });

    const validIPs = state.activeItems;
    const changed = !sameAddressSet(validIPs, originalIPs);
    if (changed) {
        if (validIPs.length === 0 && record?.id) {
            const ok = await deleteDNSRecord(cfConfig, record.id);
            addLog(ok ? `📝 TXT记录已删除（所有IP失效）` : `⚠️ TXT记录删除失败`);
        } else if (validIPs.length > 0) {
            const ok = await upsertTXTRecord(cfConfig, target.domain, record?.id, validIPs);
            addLog(ok ? (record?.id ? `📝 TXT已更新` : `📝 TXT已创建`) : `⚠️ TXT保存失败`);
        }
        report.txtUpdated = true;
    }

    await finalizeMaintenanceCore(env, poolKey, report, state, config);
}
async function maintainAllDomains(env, isManual = false, config) {
    const allReports = [];
    const startTime = Date.now();

    const poolStats = new Map();
    const poolNames = await readPoolDisplayNames(env);
    await ensurePoolDefaults(env);
    const domainPoolMapping = await readDomainPoolMapping(env);

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

    const poolKeys = await listPoolKeys(env);
    const poolSettled = await Promise.allSettled(
        poolKeys.map(async poolKey => {
            const raw = await env.IP_DATA.get(poolKey) || '';
            return [poolKey, parsePoolList(raw).length];
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
            poolKeyUsed: '',
            poolDisplayName: '',
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
        const targetPoolKey = getTargetDuplicateKey(target);
        const targetDomain = String(target.domain || '').trim().toLowerCase();
        const mappedPoolKey = domainPoolMapping?.[targetPoolKey] ?? domainPoolMapping?.[targetDomain] ?? domainPoolMapping?.[target.domain] ?? POOL_DEFAULT_KEY;
        const poolKey = isUserPoolKey(mappedPoolKey) ? mappedPoolKey : POOL_DEFAULT_KEY;
        report.poolKeyUsed = poolKey;
        report.poolDisplayName = getPoolDisplayName(poolKey, poolNames);

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
    if (poolStats.has(POOL_TRASH_KEY)) {
        const trashRaw = await env.IP_DATA.get(POOL_TRASH_KEY) || '';
        poolStats.get(POOL_TRASH_KEY).after = parsePoolList(trashRaw).length;
    }

    // 1. 检查是否有IP变化（删除或新增）
    const hasIPChanges = allReports.some(r => r.added.length > 0 || r.removed.length > 0);

    // 2. 检查是否有配置错误
    const hasConfigError = allReports.some(r => r.configError);

    // 3. 检查是否有域名活跃数不足且无法补充IP
    // 注：poolExhausted 表示候选IP不足（包括池枯竭、端口不匹配等情况）
    const hasInsufficientActive = allReports.some(r =>
        r.afterActive < r.minActive && r.poolExhausted
    );

    // 通知条件：手动执行 OR IP变化 OR 活跃数不足 OR 配置错误
    const shouldNotify = isManual || hasIPChanges || hasInsufficientActive || hasConfigError;

    let tgResult = { sent: false, reason: 'no_need' };
    if (shouldNotify && config.tgEnabled !== false) {
        tgResult = await sendTG(allReports, poolStats, isManual, { ...config, poolNames });
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
    const countries = String(item.country || '').split(/[\/,\s]+/).filter(v => !isUnknownMetaValue(v));
    const asns = String(item.asn || '').split(/[\/,\s]+/)
        .filter(v => !isUnknownMetaValue(v))
        .map(v => v.toUpperCase().startsWith('AS') ? v.toUpperCase() : 'AS' + v);
    if (countries.length) parts.push([...new Set(countries)].join('/'));
    if (asns.length) parts.push([...new Set(asns)].join('/'));
    return parts.length ? parts.join(' · ') : '无详情';
}

function formatIPChanges(added, removed, port = '', minActive = 0, afterActive = 0) {
    let msg = '';
    if (added && added.length > 0) {
        msg += `📈 新增 ${added.length} 个IP\n`;
        added.forEach(item => {
            const displayIP = hasExplicitPort(item.ip) ? item.ip : parseAddr(item.ip, port || '443').address;
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
    const poolNames = config.poolNames || {};

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
        msg += ` · 最小活跃数 ${report.minActive}\n`;
        msg += `📦 使用池: <b>${report.poolDisplayName || getPoolDisplayName(report.poolKeyUsed, poolNames)}</b>\n\n`;

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
        const displayName = getPoolDisplayName(poolKey, poolNames);
        msg += `\n<b>${displayName}</b>\n`;
        msg += `   维护前: ${stats.before} 个\n`;
        msg += `   维护后: ${stats.after} 个\n`;

        const change = stats.after - stats.before;
        if (change !== 0) {
            const changeSymbol = change > 0 ? '📈' : '📉';
            msg += `   ${changeSymbol} 变化: ${change > 0 ? '+' : ''}${change}\n`;
        }

        if (poolKey === POOL_TRASH_KEY) {
            continue;
        }

        if (stats.after === 0 && stats.before > 0) {
            msg += `   ⚠️ <b>警告：${displayName}已枯竭！</b>\n`;
        } else if (stats.after < 10) {
            msg += `   ⚠️ 库存较低\n`;
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

// ==================== UI rendering ====================

function escapeHTML(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderLoginStyles() {
    return `
  <style>
    *{box-sizing:border-box}
    body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f7;color:#1d1d1f}
    .login{width:100%;max-width:380px;background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:28px;box-shadow:0 18px 50px rgba(15,23,42,.08)}
    h1{font-size:22px;line-height:1.2;margin:0 0 8px;font-weight:750}
    p{margin:0 0 22px;color:#6b7280;font-size:13px;line-height:1.55}
    label{display:block;margin-bottom:8px;font-size:13px;font-weight:700;color:#374151}
    input{width:100%;height:44px;border:1px solid #d8dce3;border-radius:12px;padding:0 13px;font:inherit;outline:none;background:#f9fafb}
    input:focus{background:#fff;border-color:#007aff;box-shadow:0 0 0 4px rgba(0,122,255,.12)}
    button{width:100%;height:44px;margin-top:14px;border:0;border-radius:12px;background:#007aff;color:#fff;font-weight:750;font:inherit;cursor:pointer}
    button:hover{background:#0068d9}
    .hint{margin-top:14px;text-align:center;color:#9ca3af;font-size:12px}
  </style>
`;
}

function renderLoginHTML(url) {
    const cleanUrl = new URL(url.href);
    cleanUrl.searchParams.delete('key');
    const nextPath = `${cleanUrl.pathname || '/'}${cleanUrl.search}`;
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DDNS Pro - 登录</title>
  ${renderLoginStyles()}
</head>
<body>
  <form class="login" method="GET" action="${escapeHTML(nextPath || '/')}">
    <h1>DDNS Pro</h1>
    <p>该面板已开启访问保护，输入访问密钥后会保持登录状态。</p>
    <label for="key">访问密钥</label>
    <input id="key" name="key" type="password" autocomplete="current-password" autofocus required />
    <button type="submit">进入面板</button>
    <div class="hint">未配置 AUTH_KEY 时会直接进入面板</div>
  </form>
</body>
</html>`;
}

function renderAppStyles() {
    return `
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
        [hidden] { display: none !important; }
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
        .progress { display: flex; height: 1rem; overflow: hidden; font-size: .75rem; background-color: #e9ecef; border-radius: .375rem; }
        .progress-bar { display: flex; flex-direction: column; justify-content: center; overflow: hidden; color: #fff; text-align: center; white-space: nowrap; transition: width .6s ease; }
        /* ── Bootstrap replacement: Utilities - Spacing ── */
        .m-0 { margin: 0 !important; }
        .mb-0 { margin-bottom: 0 !important; }
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
        .gap-1 { gap: .25rem !important; }
        .gap-2 { gap: .5rem !important; }
        .align-items-center { align-items: center !important; }
        .justify-content-between { justify-content: space-between !important; }
        /* ── Bootstrap replacement: Utilities - Text ── */
        .text-white { color: #fff !important; }
        .text-center { text-align: center !important; }
        .text-secondary { color: var(--secondary) !important; }
        .text-danger { color: var(--danger) !important; }
        .text-decoration-none { text-decoration: none !important; }
        .fw-bold { font-weight: 700 !important; }
        .small, small { font-size: .875em; }
        /* ── Bootstrap replacement: Utilities - Size ── */
        .w-100 { width: 100% !important; }
        h6 { margin-top: 0; margin-bottom: .5rem; font-size: 1rem; font-weight: 500; }
        .hero {
            padding: 28px 0 16px;
            position: relative;
        }
        .hero h1 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--secondary);
            margin-bottom: 10px;
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
            max-width: 560px;
            margin-top: 12px;
        }
        .target-summary {
            display: inline-flex;
            width: fit-content;
            max-width: 100%;
            position: relative;
            min-height: 76px;
            padding: 18px 58px 14px 18px;
            align-items: center;
            border: 1px solid #e5e5e7;
            border-radius: 16px;
            background: rgba(255,255,255,0.9);
            box-shadow: 0 8px 24px rgba(0,0,0,0.06);
            text-align: left;
            cursor: pointer;
            overflow: hidden;
        }
        #current-target-summary-content {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 4px 10px;
            min-width: 0;
        }
        .target-summary-domain {
            display: block;
            flex: 1 1 auto;
            order: 1;
            min-width: 0;
            max-width: min(58vw, 390px);
            color: #1d1d1f;
            font-size: 1.08rem;
            font-weight: 800;
            line-height: 1.3;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .target-summary-meta {
            display: block;
            flex-basis: 100%;
            order: 3;
            margin-top: 0;
            color: #6b7280;
            font-size: .82rem;
            font-weight: 600;
        }
        .target-summary .record-badge {
            position: absolute;
            top: 8px;
            right: 10px;
            margin-left: 0;
        }
        .target-select-overlay {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }
        @media (max-width: 768px) {
            .target-summary {
                min-height: 68px;
                width: 100%;
                padding: 16px 52px 12px 12px;
            }
            .target-summary-domain {
                max-width: calc(100vw - 156px);
                font-size: 1rem;
            }
            .target-summary-meta {
                font-size: .76rem;
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
        .toolbar-row {
            display: grid;
            grid-template-columns: minmax(0, 1fr) repeat(3, auto);
            gap: 8px;
            align-items: center;
        }
        .toolbar-row .btn {
            white-space: nowrap;
        }
        .primary-actions {
            display: grid;
            grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
            gap: 8px;
            align-items: stretch;
        }
        .primary-actions .btn {
            border-radius: 10px;
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
        .config-empty-state {
            padding: 18px;
            border: 1px dashed #d8dce3;
            border-radius: 10px;
            color: #6b7280;
            background: #f8fafc;
            font-size: 13px;
            text-align: center;
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
        .pool-tools {
            display: flex;
            gap: 6px;
            align-items: center;
            flex-wrap: wrap;
        }
        .pool-tools .form-select {
            width: 160px;
            border-radius: 8px;
        }
        .domain-binding-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            cursor: pointer;
            margin-bottom: 0;
            list-style: none;
        }
        .domain-binding-header::-webkit-details-marker {
            display: none;
        }
        .domain-binding-card[open] .domain-binding-header {
            margin-bottom: 1rem;
        }
        .domain-binding-header h6 {
            min-width: 0;
        }
        .domain-binding-table-wrap {
            max-height: 280px;
            overflow: auto;
            border: 1px solid #e8edf5;
            border-radius: 12px;
            -webkit-overflow-scrolling: touch;
        }
        .domain-binding-table-wrap::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        .domain-binding-table-wrap::-webkit-scrollbar-thumb {
            background: #d1d1d6;
            border-radius: 3px;
        }
        .domain-binding-table-wrap .table {
            table-layout: fixed;
            width: 100%;
            min-width: 0;
            margin-bottom: 0;
        }
        .domain-binding-table-wrap th:first-child,
        .domain-binding-table-wrap td:first-child {
            width: 58%;
        }
        .domain-binding-table-wrap th:last-child,
        .domain-binding-table-wrap td:last-child {
            width: 42%;
        }
        .domain-binding-table-wrap thead {
            position: sticky;
            top: 0;
            z-index: 1;
            background: #fff;
        }
        .domain-binding-table-wrap th,
        .domain-binding-table-wrap td {
            padding: 10px 12px;
        }
        .domain-binding-domain {
            display: grid;
            grid-template-columns: 24px minmax(0, 1fr);
            align-items: center;
            gap: 8px;
            max-width: 100%;
            overflow: hidden;
        }
        .domain-binding-domain .record-badge {
            justify-content: center;
            width: 24px;
            margin-left: 0;
            padding: 0;
        }
        .domain-binding-name {
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .record-badge {
            display: inline-flex;
            align-items: center;
            height: 18px;
            margin-left: 8px;
            padding: 0 6px;
            border-radius: 999px;
            font-size: 10px;
            font-weight: 700;
            line-height: 1;
            letter-spacing: 0;
            vertical-align: middle;
            border: 1px solid transparent;
        }
        .record-badge-a {
            color: #0b5cab;
            background: #e8f2ff;
            border-color: #b8d7ff;
        }
        .record-badge-txt {
            color: #087443;
            background: #e6f7ee;
            border-color: #a8e3c3;
        }
        .domain-binding-select {
            width: 100%;
            min-width: 0;
        }
        .filter-line {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 34px repeat(3, minmax(58px, 76px));
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
            margin-top: 8px;
            padding: 10px 12px;
            border-radius: 10px;
            background: #f5f5f7;
            color: #4b5563;
            font-size: 12px;
            line-height: 1.55;
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
        .pill-badge, .latency-badge, .colo-badge {
            display: inline-flex;
            justify-content: center;
            align-items: center;
            border-radius: 999px;
            padding: 5px 9px;
            font-size: 12px;
            font-weight: 700;
            line-height: 1.15;
            white-space: nowrap;
        }
        .latency-badge {
            min-width: 64px;
            color: #1d4ed8;
            background: #dbeafe;
        }
        .colo-badge {
            min-width: 48px;
            color: #374151;
            background: #f3f4f6;
        }
        .address-pill {
            max-width: 240px;
            min-width: 150px;
            font-family: 'SF Mono', Consolas, monospace;
            color: #0f172a;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            overflow: hidden;
            text-overflow: ellipsis;
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
        .config-toolbar {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .config-details {
            overflow: hidden;
        }
        .config-details-summary {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
            cursor: pointer;
            list-style: none;
        }
        .config-details-summary::-webkit-details-marker {
            display: none;
        }
        .config-details-summary::after {
            content: '展开';
            color: #6b7280;
            font-size: 12px;
            background: #f5f5f7;
            border-radius: 999px;
            padding: 6px 10px;
        }
        .config-details[open] .config-details-summary::after {
            content: '收起';
        }
        .config-details-body {
            padding-top: 16px;
        }
        #page-config button:disabled {
            opacity: .55;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
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
            display: inline-flex;
            align-items: center;
            background: #e8f4ff;
            color: var(--primary);
            padding: 3px 7px;
            border-radius: 999px;
            font-size: 11px;
            line-height: 1.2;
            white-space: nowrap;
        }
        .exit-list-cell {
            min-width: 500px;
            text-align: left;
            max-width: 560px;
            overflow: hidden;
        }
        .exit-detail {
            display: grid;
            grid-template-columns: 54px minmax(140px, 1fr) minmax(86px, 128px) minmax(110px, 180px);
            gap: 8px;
            align-items: center;
            margin: 2px 0;
            padding: 4px 0;
            border-bottom: 1px solid rgba(0,0,0,.05);
            min-height: 30px;
            width: 100%;
            min-width: 100%;
        }
        .exit-detail.is-dual {
            background: linear-gradient(90deg, rgba(52,199,89,.08), rgba(0,122,255,.06));
            border-radius: 8px;
            padding: 5px 6px;
        }
        .exit-detail:last-child {
            border-bottom: 0;
        }
        .exit-ip {
            font-family: 'SF Mono', Consolas, monospace;
            font-weight: 700;
            color: #1d1d1f;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-size: 11px;
            line-height: 1.25;
            cursor: pointer;
            border: 1px solid #e2e8f0;
            background: #fff;
            border-radius: 999px;
            padding: 5px 9px;
            min-width: 0;
            width: 100%;
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
            max-width: 260px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            background: #eef6ff;
            color: #0b65d8;
        }
        @media (max-width: 768px) {
            .ip-info-tag {
                font-size: 9px;
                padding: 2px 4px;
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
            .pool-tools {
                width: 100%;
                display: grid;
                grid-template-columns: minmax(0, 1fr) repeat(4, 38px);
            }
            .pool-tools .form-select {
                width: 100%;
            }
            .domain-binding-table-wrap {
                max-height: 240px;
            }
            .domain-binding-table-wrap th,
            .domain-binding-table-wrap td {
                padding: 8px;
            }
            .domain-binding-select {
                font-size: 11px;
                padding: 6px 28px 6px 8px;
            }
            .exit-list-cell {
                min-width: 480px;
            }
            .exit-detail {
                grid-template-columns: 48px minmax(120px, 1fr) minmax(72px, 108px) minmax(110px, 150px);
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
            .toolbar-row {
                grid-template-columns: minmax(0, 1fr) repeat(3, 38px);
                gap: 6px;
            }
            .toolbar-row .btn {
                padding-left: 8px !important;
                padding-right: 8px !important;
            }
            .primary-actions {
                grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
            }
            .primary-actions .btn-outline-secondary {
                grid-column: 1 / -1;
            }
            /* 筛选工具栏移动端适配 */
            .filter-toolbar {
                display: block !important;
            }
            .filter-line {
                grid-template-columns: minmax(0, 1fr) 34px repeat(3, minmax(54px, 1fr));
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
`;
}

function renderGithubCorner() {
    return `
<a href="https://github.com/231128ikun/DDNS-cf-proxyip" class="github-corner" aria-label="View source on GitHub" target="_blank">
    <svg viewBox="0 0 250 250" aria-hidden="true">
        <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
        <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
        <path d="M115.0,115.0 C114.9,115.1 118.7,116.6 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.6 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
</a>
`;
}

function renderHero(C, kvReady) {
    return `
<div class="container hero">
    <h1>
        🌐 DDNS Pro 多域名管理
    </h1>
    <div class="hero-actions">
        <div class="guide-toggle" onclick="toggleHidden('usage-guide')" title="使用步骤提示">?</div>
        <div class="config-info">
            🧭 建议流程：导入IP → 检测 → 入库 → 执行维护
        </div>
    </div>
    ${kvReady ? '' : `<div class="kv-alert"><strong>KV 未绑定。</strong>请在 Worker Settings &gt; Bindings 中绑定 KV Namespace，变量名必须为 <code>IP_DATA</code>。未绑定前配置保存、IP 池、维护任务都不可用。</div>`}
    <div id="usage-guide" class="usage-guide" hidden>
        <ol>
            <li><strong>准备IP</strong>：在左侧 <code>IP库管理</code> 中手动输入或远程加载 IP，点击【⚡ 检测】筛出可用 IP。</li>
            <li><strong>保存到池</strong>：选择上方的 IP 池（默认为默认池），点击【💾 入库】将可用 IP 入库。</li>
            <li><strong>执行维护</strong>：在顶部选择要维护的域名，点击右侧【🔧 执行全部维护】或依靠定时任务自动维护。</li>
        </ol>
    </div>
    <div class="domain-selector">
        <label class="target-summary">
            <span id="current-target-summary-content">
                <span class="target-summary-domain">未配置维护域名</span>
                <span class="target-summary-meta">请先到配置中心添加</span>
            </span>
            <select id="domain-select" class="target-select-overlay" onchange="switchDomain()" aria-label="选择维护域名">
                ${C.targets.map((t, i) => {
                    const modeLabel = {'A': 'A/AAAA', 'TXT': 'TXT'};
                    const label = `${t.domain} - ${modeLabel[t.mode] || t.mode}`;
                    return `<option value="${i}">${escapeHTML(label)}</option>`;
                }).join('')}
            </select>
        </label>
    </div>
</div>
`;
}

function renderTopNav() {
    return `
    <div class="top-nav">
        <button class="nav-tab active" data-page="dashboard" onclick="showPage('dashboard')">运行面板</button>
        <button class="nav-tab" data-page="config" onclick="showPage('config')">配置中心</button>
    </div>
`;
}

function renderConfigToggleField(field) {
    return `
                <label class="switch">
                    <input type="checkbox" id="${escapeHTML(field.id)}">
                    <span class="switch-slider"></span>
                    <span>${escapeHTML(field.label)}</span>
                </label>`;
}

function renderConfigInputField(field) {
    const limits = SETTING_LIMITS[field.key] || {};
    const classes = ['field', field.span ? `span-${field.span}` : ''].filter(Boolean).join(' ');
    const type = CONFIG_NUMBER_FIELDS.includes(field) ? 'number' : 'text';
    const minAttr = limits.min === undefined ? '' : ` min="${limits.min}"`;
    const maxAttr = limits.max === undefined ? '' : ` max="${limits.max}"`;
    return `<label class="${escapeHTML(classes)}"><span>${escapeHTML(field.label)}</span><small>${escapeHTML(field.help)}</small><input id="${escapeHTML(field.id)}" type="${type}"${minAttr}${maxAttr} class="form-control form-control-sm" placeholder="${escapeHTML(field.placeholder)}"></label>`;
}

function renderConfigPage() {
    return `
    <div id="page-config" class="page-panel">
        <details class="card p-4 mb-3 config-details">
            <summary class="config-details-summary">
                <h6 class="m-0 fw-bold">⚙️ 基础配置</h6>
                <div class="config-toolbar">
                    <button id="btn-cancel-config" class="btn btn-sm btn-outline-secondary" onclick="event.preventDefault(); resetConfigDraft()" hidden>还原改动</button>
                    <button id="btn-save-config" class="btn btn-sm btn-success config-save-btn" onclick="event.preventDefault(); saveAppConfig()" hidden>💾 保存到 KV</button>
                </div>
            </summary>
            <div class="config-details-body">
                <div class="switch-row mb-3">
                    ${CONFIG_TOGGLE_FIELDS.map(renderConfigToggleField).join('\n')}
                </div>
                <div class="config-grid mb-3">
                    ${CONFIG_TEXT_FIELDS.concat(CONFIG_NUMBER_FIELDS).map(renderConfigInputField).join('\n')}
                </div>
            </div>
        </details>

        <div class="card p-4 mb-3">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h6 class="m-0 fw-bold">🌐 维护的域名配置</h6>
                <button class="btn btn-sm btn-outline-primary config-add-action" onclick="addZoneConfigRow()">➕ 添加权限配置</button>
            </div>
            <div id="zone-config-list" class="config-card-grid"></div>
            <div id="zone-edit-panel" class="config-edit-panel"></div>
        </div>

        <div class="card p-4 mb-3">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h6 class="m-0 fw-bold">🧭 管理域名</h6>
                <button class="btn btn-sm btn-outline-primary config-add-action" onclick="addTargetConfigRow()">➕ 添加管理域名</button>
            </div>
            <div id="target-config-list" class="config-card-grid"></div>
            <div id="target-edit-panel" class="config-edit-panel"></div>
        </div>
    </div>
`;
}

function renderDashboardPage() {
    return `
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
                            <th>Colo</th>
                            <th>延迟</th>
                            <th>状态</th>
                            <th>出口IP / 线路</th>
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
                    <div class="pool-tools">
                        <select id="pool-selector" class="form-select form-select-sm" onchange="switchPool()">
                            <option value="${POOL_DEFAULT_KEY}">默认池</option>
                        </select>
                        <button class="btn btn-sm" onclick="createNewPool()" title="新建池" style="padding:6px 8px">➕</button>
                        <button class="btn btn-sm" onclick="renameCurrentPool()" title="重命名池" style="padding:6px 8px">✏️</button>
                        <button class="btn btn-sm" onclick="deleteCurrentPool()" title="删除池" style="padding:6px 8px">🗑️</button>
                        <button class="btn btn-sm" onclick="oneClickClean()" title="一键洗库" style="padding:6px 8px">🧹</button>
                    </div>
                </div>

                <!-- 内容区域 - 自动扩展 -->
                <div class="ip-content-area">
                    <!-- 加载区 -->
                    <div class="toolbar-row mb-2">
                        <input type="text" id="remote-url" class="form-control form-control-sm flex-grow-1" placeholder="远程TXT URL" style="border-radius:8px">
                        <button class="btn btn-sm btn-outline-primary" onclick="loadRemoteUrl()" style="white-space:nowrap" title="从远程URL加载">🌐 加载</button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="loadCurrentPool()" title="加载当前池到输入框" style="white-space:nowrap">📂 从库</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="clearInput()" title="清空输入框" style="white-space:nowrap">🗑️ 清空</button>
                    </div>

                    <!-- 输入区 -->
                    <textarea id="ip-input" class="form-control mb-2" rows="6" placeholder="支持格式：&#10;1.2.3.4:443&#10;1.2.3.4 (默认443端口)&#10;example.com:8443 (检测时解析为IP)&#10;1.2.3.4:443 #HK 香港节点 (带注释)" style="border-radius:12px;font-family:'SF Mono',monospace;font-size:12px"></textarea>

                    <!-- 筛选工具 -->
                    <div class="mb-2 filter-toolbar">
                        <div class="filter-line">
                            <input type="text" id="universal-filter" class="form-control form-control-sm" style="border-radius:8px" placeholder="筛选">
                            <button class="filter-help-btn" onclick="toggleHidden('filter-help')" title="筛选用法">?</button>
                            <button class="btn btn-sm btn-outline-success" onclick="smartFilter('keep')" title="保留匹配的IP">保留</button>
                            <button class="btn btn-sm btn-outline-danger" onclick="smartFilter('exclude')" title="排除匹配的IP">排除</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="quickDeduplicate()" title="去除重复IP">去重</button>
                        </div>
                        <div id="filter-help" class="filter-help" hidden>
                            支持空格分隔条件：<code>port:443</code>、<code>port:443-2053</code>、<code>country:国家代码</code>、<code>asn:ASN编号</code>、普通关键词。空格表示“且”，竖线 <code>|</code> 表示“或”,例如 <code>country:KR asn:AS4766 | country:US</code>
                        </div>
                        <div id="filter-preview" class="filter-preview">输入条件后会显示匹配数量。</div>
                        <span class="text-secondary small pool-stat" title="当前池中IP数量">📊<span id="pool-count">0</span></span>
                    </div>
                </div>

                <!-- 底部按钮区域 - 固定在底部 -->
                <div class="ip-actions-area mt-auto">
                    <!-- 主操作按钮 -->
                    <div class="primary-actions" id="main-actions">
                        <button id="btn-check" class="btn btn-primary" onclick="batchCheck()">⚡ 检测</button>
                        <button class="btn btn-success" onclick="saveToCurrentPool('append')">💾 入库</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="removeFromPool()" title="从库中移除输入框中的IP">从库中移除</button>
                    </div>

                    <!-- 垃圾桶专用操作 -->
                    <div id="trash-actions" class="mt-2" hidden>
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
            <details id="domain-binding-card" class="card p-4 mb-3 domain-binding-card">
                <summary class="domain-binding-header" title="点击展开/折叠域名池绑定">
                    <h6 class="m-0 fw-bold">🔗 域名池绑定</h6>
                    <button class="btn btn-sm btn-outline-primary" onclick="event.preventDefault(); event.stopPropagation(); loadDomainPoolMapping()" title="刷新">🔄</button>
                </summary>
                <div class="domain-binding-table-wrap">
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
            </details>

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
`;
}

function renderClientScript({ targetsJson, settingsJson, appConfigJson, authEnabled }) {
    return `
<script>
    // ===== Client state =====
    const TARGETS = ${targetsJson};
    let SETTINGS = ${settingsJson};
    const INITIAL_APP_CONFIG = ${appConfigJson};
    const AUTH_ENABLED = ${authEnabled ? 'true' : 'false'};
    const MODE_LABELS = {'A': 'A/AAAA', 'TXT': 'TXT'};
    const CONFIG_TEXT_FIELDS = ${JSON.stringify(CONFIG_TEXT_FIELDS.map(({ key, id }) => [key, id]))};
    const CONFIG_NUMBER_FIELDS = ${JSON.stringify(CONFIG_NUMBER_FIELDS.map(({ key, id }) => [key, id]))};
    const CONFIG_TOGGLE_FIELDS = ${JSON.stringify(CONFIG_TOGGLE_FIELDS.map(({ key, id, fallback }) => [key, id, fallback]))};
    let currentTargetIndex = 0;
    const POOL_DEFAULT_KEY = '${POOL_DEFAULT_KEY}';
    const POOL_TRASH_KEY = '${POOL_TRASH_KEY}';
    let currentPool = POOL_DEFAULT_KEY;
    let abortController = null;
    let domainPoolMapping = {};
    let availablePools = [POOL_DEFAULT_KEY];
    let poolDisplayNames = {};
    let toastTimer = null;
    let configDraft = null;
    let configSavedSnapshot = null;
    let configDirty = false;
    // 检测中断状态
    let pausedCheckState = null; // { uncheckedLines: [], validIPs: [], total: number }

    const byId = id => document.getElementById(id);
    const nonEmptyLines = text => String(text || '').split('\\n').filter(line => line.trim());
    const getInputLines = id => {
        const el = byId(id);
        return el ? nonEmptyLines(el.value) : [];
    };
    const setElementValue = (id, value) => {
        const el = byId(id);
        if (el) el.value = value || '';
    };
    const setInputValueAndPreview = (id, value) => {
        setElementValue(id, value);
        updateFilterPreview();
    };


    // ===== Modal / small UI helpers =====
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

            byId('modal-continue').onclick = () => {
                document.body.removeChild(overlay);
                resolve(true);
            };
            byId('modal-abandon').onclick = () => {
                document.body.removeChild(overlay);
                resolve(false);
            };
        });
    }

    // 池名显示（统一格式）
    const POOL_NAMES = { [POOL_DEFAULT_KEY]: '默认池', [POOL_TRASH_KEY]: '🗑️ 垃圾桶' };
    const NUMBERED_POOL_KEY_RE = /^ip_pool_(\\d{3})$/;
    function getPoolName(key) {
        if (poolDisplayNames[key]) return poolDisplayNames[key];
        if (POOL_NAMES[key]) return POOL_NAMES[key];
        const numbered = NUMBERED_POOL_KEY_RE.exec(key || '');
        if (numbered) return \`池 \${numbered[1]}\`;
        return String(key || '').replace(/^ip_pool_/, '池 ');
    }
    function getPoolFixedName(key) {
        if (POOL_NAMES[key]) return POOL_NAMES[key];
        const numbered = NUMBERED_POOL_KEY_RE.exec(key || '');
        if (numbered) return \`池 \${numbered[1]}\`;
        return getPoolName(key);
    }
    function comparePoolKeys(a, b) {
        const order = key => key === POOL_DEFAULT_KEY ? 0 : (key === POOL_TRASH_KEY ? 1 : 2);
        const oa = order(a);
        const ob = order(b);
        if (oa !== ob) return oa - ob;
        const na = NUMBERED_POOL_KEY_RE.exec(a || '');
        const nb = NUMBERED_POOL_KEY_RE.exec(b || '');
        if (na && nb) return Number(na[1]) - Number(nb[1]);
        if (na) return -1;
        if (nb) return 1;
        return String(a || '').localeCompare(String(b || ''), 'zh-CN', { numeric: true });
    }

    function getBoundPoolForTarget(target = {}) {
        const key = getTargetDuplicateKey(target);
        const domain = String(target.domain || '').trim().toLowerCase();
        return domainPoolMapping[key] || domainPoolMapping[domain] || domainPoolMapping[target.domain] || POOL_DEFAULT_KEY;
    }

    function renderTargetSummary(target = {}) {
        if (!target.domain) {
            return '<span class="target-summary-domain">未配置维护域名</span><span class="target-summary-meta">请先到配置中心添加</span>';
        }
        const mode = target.mode === 'TXT' ? 'TXT' : 'A';
        const modeLabel = MODE_LABELS[mode] || mode;
        const modeShortLabel = mode === 'TXT' ? 'T' : 'A';
        const port = String(target.port || '').trim();
        const meta = mode !== 'TXT' && port && port !== 'any' ? '端口 ' + port : modeLabel + ' 记录';
        return '<span class="record-badge record-badge-' + mode.toLowerCase() + '" title="' + escapeHTML(modeLabel) + '">' + escapeHTML(modeShortLabel) + '</span>' +
            '<span class="target-summary-domain">' + escapeHTML(target.domain) + '</span>' +
            '<span class="target-summary-meta">' + escapeHTML(meta) + '</span>';
    }

    function applyPoolState(state = {}) {
        domainPoolMapping = state.mapping && typeof state.mapping === 'object' && !Array.isArray(state.mapping) ? state.mapping : {};
        availablePools = Array.isArray(state.pools) && state.pools.length ? state.pools : [POOL_DEFAULT_KEY, POOL_TRASH_KEY];
        poolDisplayNames = state.poolNames && typeof state.poolNames === 'object' && !Array.isArray(state.poolNames) ? state.poolNames : {};
        if (!availablePools.includes(currentPool)) currentPool = POOL_DEFAULT_KEY;
        updatePoolSelector();
        updateDomainBindingTable();
    }

    // ===== Form / toast / navigation helpers =====
    function setInputValue(id, value) {
        const el = byId(id);
        if (el) el.value = value || '';
    }

    function getInputValue(id) {
        const el = byId(id);
        return el ? el.value.trim() : '';
    }

    function getNumberInputValue(id, fallback) {
        const value = parseInt(getInputValue(id), 10);
        return Number.isFinite(value) ? value : fallback;
    }

    function showToast(message, type = 'success') {
        const el = byId('toast');
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

    function toggleHidden(id) {
        const el = byId(id);
        if (el) el.hidden = !el.hidden;
    }

    function resetConfigDraft() {
        loadAppConfigToForm(configSavedSnapshot || INITIAL_APP_CONFIG, false);
        closeConfigEditor('zone');
        closeConfigEditor('target');
        showToast('已还原未保存改动');
    }

    function cloneConfig(config) {
        return JSON.parse(JSON.stringify(config || {}));
    }

    function setConfigDirty(dirty, message) {
        configDirty = dirty;
        document.querySelectorAll('#btn-save-config,#btn-cancel-config').forEach(btn => {
            btn.hidden = !configDirty;
        });
        if (message) showToast(message, 'info');
    }

    // ===== Config center =====
    function normalizeDraftZone(zone = {}, index = 0) {
        const label = String(zone.label || zone.name || zone.baseDomain || '').trim();
        return {
            name: label,
            label,
            baseDomain: String(zone.baseDomain || '').trim(),
            zoneId: String(zone.zoneId || '').trim(),
            apiKey: String(zone.apiKey || '').trim()
        };
    }

    function hasZoneConfigValue(zone = {}) {
        return Boolean(String(zone.baseDomain || '').trim() || String(zone.zoneId || '').trim() || String(zone.apiKey || '').trim());
    }

    function normalizeConfigCompareValue(value) {
        return String(value || '').trim().toLowerCase();
    }

    function findDuplicateDraftValue(items, keyFn, skipIndex = -1) {
        const seen = new Set();
        for (let i = 0; i < (items || []).length; i++) {
            if (i === skipIndex) continue;
            const key = normalizeConfigCompareValue(keyFn(items[i]));
            if (!key) continue;
            if (seen.has(key)) return key;
            seen.add(key);
        }
        return '';
    }

    function getZoneDuplicateMessage(zones, skipIndex = -1) {
        const duplicateBaseDomain = findDuplicateDraftValue(zones, zone => zone.baseDomain, skipIndex);
        if (duplicateBaseDomain) return '权限配置重复：' + duplicateBaseDomain;
        return '';
    }

    function getTargetDuplicateKey(target = {}) {
        const domain = normalizeConfigCompareValue(target.domain || computeDomainFromTarget(target));
        const mode = target.mode === 'TXT' ? 'TXT' : 'A';
        return domain ? domain + '|' + mode : '';
    }

    function formatTargetDuplicateKey(key) {
        const parts = String(key || '').split('|');
        const domain = parts[0] || '';
        const mode = parts[1] === 'TXT' ? 'TXT' : 'A/AAAA';
        return domain + ' / ' + mode;
    }

    function getTargetDuplicateMessage(targets, skipIndex = -1) {
        const duplicateTarget = findDuplicateDraftValue(targets, getTargetDuplicateKey, skipIndex);
        return duplicateTarget ? '管理域名重复：' + formatTargetDuplicateKey(duplicateTarget) : '';
    }

    function getDraftZones() {
        if (!configDraft) configDraft = cloneConfig(INITIAL_APP_CONFIG);
        configDraft.zones = (Array.isArray(configDraft.zones) ? configDraft.zones : [])
            .map(normalizeDraftZone)
            .filter(hasZoneConfigValue);
        return configDraft.zones;
    }

    function getDraftTargets() {
        if (!configDraft) configDraft = cloneConfig(INITIAL_APP_CONFIG);
        configDraft.targets = (Array.isArray(configDraft.targets) ? configDraft.targets : [])
            .filter(target => target && typeof target === 'object');
        return configDraft.targets;
    }

    function getZoneDisplayName(index) {
        const zone = getDraftZones()[index] || {};
        return zone.baseDomain || zone.label || zone.zoneId
            ? [zone.label || zone.name || zone.baseDomain || '未命名权限配置', zone.baseDomain].filter((value, itemIndex, values) => value && values.indexOf(value) === itemIndex).join(' · ')
            : '未选择权限配置';
    }

    function computeDomainFromTarget(target = {}) {
        const zones = getDraftZones();
        const zone = zones[parseInt(target.zoneIndex || 0, 10)] || zones[0] || {};
        const baseDomain = zone.baseDomain || target.baseDomain || '';
        const prefix = String(target.prefix || '').trim().replace(/^\\.+|\\.+$/g, '');
        return baseDomain ? (prefix ? prefix + '.' + baseDomain : baseDomain) : String(target.domain || '').trim();
    }

    function renderConfigCards() {
        renderZoneConfigRows(getDraftZones());
        renderTargetConfigRows(getDraftTargets());
    }

    const ZONE_SAVED_MSG = '权限配置已保存到页面，点击“保存到 KV”后生效';
    const TARGET_SAVED_MSG = '管理域名已保存到页面，点击“保存到 KV”后生效';

    function applyConfigDraftChange(key, value, editorType, message) {
        configDraft[key] = value;
        renderConfigCards();
        closeConfigEditor(editorType);
        setConfigDirty(true, message);
    }

    function renderConfigRows(listId, rows, draftKey, renderCard, emptyHtml) {
        const list = byId(listId);
        if (!list) return;
        if (configDraft) configDraft[draftKey] = rows;
        list.innerHTML = rows.length ? rows.map((item, index) => renderCard(item, index)).join('') : emptyHtml;
    }

    function renderZoneConfigRows(zones) {
        const rows = (Array.isArray(zones) ? zones : []).map(normalizeDraftZone).filter(hasZoneConfigValue);
        renderConfigRows('zone-config-list', rows, 'zones', buildZoneCard, '<div class="config-empty-state">暂无权限配置，点击“添加权限配置”创建。</div>');
    }

    function buildZoneCard(zone = {}, index = 0) {
        const title = zone.label || zone.name || zone.baseDomain || '未命名权限配置';
        return \`
            <div class="config-mini-card" onclick="editZoneConfig(\${index})">
                <h5>\${escapeHTML(title)}</h5>
                <div class="meta"><span>\${escapeHTML(zone.baseDomain || '未设置维护域名')}</span></div>
                <div class="meta"><span>Zone: \${escapeHTML(zone.zoneId ? '已填写' : '未填写')}</span><span>CF Key: \${escapeHTML(zone.apiKey ? '已填写' : '未填写')}</span></div>
                <div class="actions" onclick="event.stopPropagation()">
                    <button class="btn btn-outline-primary btn-sm config-edit-action" onclick="editZoneConfig(\${index})">编辑</button>
                    <button class="btn btn-outline-danger btn-sm config-edit-action" onclick="deleteZoneConfig(\${index})">删除</button>
                </div>
            </div>
        \`;
    }

    function addZoneConfigRow() {
        const zones = getDraftZones();
        showZoneEditor(zones.length, { label: '', baseDomain: '', zoneId: '', apiKey: '' });
    }

    function collectZoneConfigRows() {
        return getDraftZones().map(normalizeDraftZone).filter(zone => zone.baseDomain || zone.zoneId || zone.apiKey);
    }

    function getZoneOptionsHtml(selectedIndex) {
        const zones = getDraftZones();
        if (!zones.length) {
            return '<option value="" disabled selected>请先添加权限配置</option>';
        }
        return zones.map((zone, index) => {
            const label = [zone.label || zone.name || zone.baseDomain || '未命名权限配置', zone.baseDomain].filter((value, itemIndex, values) => value && values.indexOf(value) === itemIndex).join(' · ');
            return \`<option value="\${index}" \${Number(selectedIndex) === index ? 'selected' : ''}>\${escapeHTML(label)}</option>\`;
        }).join('');
    }

    function editZoneConfig(index) {
        showZoneEditor(index, getDraftZones()[index] || {});
    }

    function openConfigEditor(type, title, content) {
        const panel = byId(type === 'zone' ? 'zone-edit-panel' : 'target-edit-panel');
        if (!panel) return null;
        panel.classList.add('active');
        panel.innerHTML = '<h6 class="mb-3 fw-bold">' + title + '</h6>' + content;
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        return panel;
    }

    function renderField(tag, { id, label, hint = '', value = '', placeholder = '', className = 'form-control form-control-sm', attrs = '' }, content = '') {
        const body = tag === 'select'
            ? '<select id="' + id + '" class="' + className + '" ' + attrs + '>' + content + '</select>'
            : '<input id="' + id + '" class="' + className + '" value="' + escapeHTML(value) + '" placeholder="' + placeholder + '" ' + attrs + '>';
        return '<label class="field"><span>' + label + '</span><small>' + hint + '</small>' + body + '</label>';
    }

    function renderEditorActions(type, submitAction) {
        return '<div class="config-edit-actions"><button class="btn btn-outline-secondary btn-sm" onclick="closeConfigEditor(&quot;' + escapeHTML(type) + '&quot;)">取消</button><button class="btn btn-primary btn-sm" onclick="' + submitAction + '">保存到页面</button></div>';
    }

    function showZoneEditor(index, zone = {}) {
        const panel = byId('zone-edit-panel');
        if (!panel) return;
        const noteValue = zone.label && zone.label !== zone.baseDomain
            ? zone.label
            : (zone.name && zone.name !== zone.baseDomain ? zone.name : '');
        const zoneFields = [
            renderField('input', { id: 'edit-zone-label', label: '备注', hint: '可选；不填时使用维护域名。', value: noteValue, placeholder: '可选' }),
            renderField('input', { id: 'edit-zone-base', label: '目标维护域名', hint: '目前只支持托管在cf的域名', value: zone.baseDomain || '', placeholder: 'example.com' }),
            renderField('input', { id: 'edit-zone-id', label: 'Zone ID', hint: 'Cloudflare 区域 ID。', value: zone.zoneId || '', placeholder: 'Zone ID' }),
            '<label class="field span-2"><span>CF Key</span><small>需要 DNS 编辑权限。</small><input id="edit-zone-key" class="form-control form-control-sm" value="' + escapeHTML(zone.apiKey || '') + '" placeholder="CF API Token"></label>'
        ].join('');
        openConfigEditor('zone', (index >= getDraftZones().length ? '添加' : '编辑') + '权限配置', '<div class="config-edit-grid">' + zoneFields + '</div>' + renderEditorActions('zone', 'commitZoneEditor(' + index + ')'));
    }

    function commitZoneEditor(index) {
        const zones = getDraftZones();
        const nextZone = normalizeDraftZone({
            label: getInputValue('edit-zone-label'),
            baseDomain: getInputValue('edit-zone-base'),
            zoneId: getInputValue('edit-zone-id'),
            apiKey: getInputValue('edit-zone-key')
        }, index);
        if (!hasZoneConfigValue(nextZone)) {
            showToast('请至少填写目标维护域名、Zone ID 或 CF Key', 'error');
            return;
        }
        const nextZones = zones.slice();
        nextZones[index] = nextZone;
        const duplicateMessage = getZoneDuplicateMessage(nextZones);
        if (duplicateMessage) {
            showToast(duplicateMessage, 'error');
            return;
        }
        applyConfigDraftChange('zones', nextZones, 'zone', ZONE_SAVED_MSG);
    }

    function deleteZoneConfig(index) {
        const zones = getDraftZones();
        if (!confirm('确认删除这个权限配置？相关管理域名会改到第一组权限配置。')) return;
        zones.splice(index, 1);
        configDraft.targets = getDraftTargets().map(target => ({
            ...target,
            zoneIndex: target.zoneIndex === index ? 0 : (target.zoneIndex > index ? target.zoneIndex - 1 : target.zoneIndex)
        }));
        applyConfigDraftChange('zones', zones.map(normalizeDraftZone).filter(hasZoneConfigValue), 'zone', ZONE_SAVED_MSG);
    }

    function closeConfigEditor(type) {
        const panel = byId(type === 'zone' ? 'zone-edit-panel' : 'target-edit-panel');
        if (panel) {
            panel.classList.remove('active');
            panel.innerHTML = '';
        }
    }

    function renderTargetConfigRows(targets) {
        const rows = (Array.isArray(targets) ? targets : []).filter(target => target && typeof target === 'object');
        renderConfigRows('target-config-list', rows, 'targets', buildTargetCard, '<div class="config-empty-state">暂无管理域名，点击“添加管理域名”创建。</div>');
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
                <h5>\${escapeHTML(domain || '等待生成')}</h5>
                <div class="meta"><span>\${escapeHTML(meta)}</span><span>\${escapeHTML(exitLabel)}</span><span>\${escapeHTML(getZoneDisplayName(target.zoneIndex || 0))}</span><span>\${enabled ? '维护开启' : '维护关闭'}</span></div>
                <div class="meta"><span>活跃数 \${escapeHTML(String(target.minActive ?? 3))}</span>\${filters ? '<span>' + escapeHTML(filters) + '</span>' : ''}</div>
                <div class="actions" onclick="event.stopPropagation()">
                    <label class="switch" title="单独控制这个域名是否参与维护">
                        <input type="checkbox" \${enabled ? 'checked' : ''} onchange="toggleTargetEnabled(\${index}, this.checked)">
                        <span class="switch-slider"></span>
                    </label>
                    <button class="btn btn-outline-primary btn-sm config-edit-action" onclick="editTargetConfig(\${index})">编辑</button>
                    <button class="btn btn-outline-danger btn-sm config-edit-action" onclick="deleteTargetConfig(\${index})">删除</button>
                </div>
            </div>
        \`;
    }

    function addTargetConfigRow() {
        if (!getDraftZones().length) {
            showToast('请先添加权限配置，再创建管理域名', 'error');
            return;
        }
        showTargetEditor(getDraftTargets().length, { mode: 'A', zoneIndex: 0, prefix: '', port: '443', minActive: (configDraft?.settings?.DEFAULT_MIN_ACTIVE ?? SETTINGS.DEFAULT_MIN_ACTIVE) });
    }

    function loadAppConfigToForm(config, updateSnapshot = true) {
        configDraft = cloneConfig(config);
        if (updateSnapshot) configSavedSnapshot = cloneConfig(config);
        CONFIG_TEXT_FIELDS.forEach(([key, id]) => setInputValue(id, config[key]));
        const settings = config.settings || SETTINGS;
        CONFIG_NUMBER_FIELDS.forEach(([key, id]) => setInputValue(id, settings[key] ?? SETTINGS[key]));
        CONFIG_TOGGLE_FIELDS.forEach(([key, id, fallback]) => {
            const el = byId(id);
            if (el) el.checked = config[key] === undefined ? fallback : config[key] !== false;
        });
        renderConfigCards();
        setConfigDirty(false);
    }

    function collectTargetConfigRows() {
        return getDraftTargets().map(target => ({
            ...target,
            domain: computeDomainFromTarget(target)
        })).filter(target => target.domain);
    }

    function editTargetConfig(index) {
        showTargetEditor(index, (getDraftTargets()[index] || {}));
    }

    function showTargetEditor(index, target = {}) {
        const panel = byId('target-edit-panel');
        if (!panel) return;
        const mode = target.mode === 'TXT' ? 'TXT' : 'A';
        const modeOptions = ['A', 'TXT'].map(value => \`<option value="\${value}" \${mode === value ? 'selected' : ''}>\${MODE_LABELS[value]}</option>\`).join('');
        const exit = target.exitFilter || 'any';
        const portValue = mode === 'TXT' ? '任意' : (target.port || '443');
        const previousAPort = mode === 'TXT' && target.port && target.port !== 'any' ? target.port : '443';
        const exitOptions = '<option value="any" ' + (exit === 'any' ? 'selected' : '') + '>任意</option><option value="v4" ' + (exit === 'v4' ? 'selected' : '') + '>IPv4</option><option value="v6" ' + (exit === 'v6' ? 'selected' : '') + '>IPv6</option><option value="dual" ' + (exit === 'dual' ? 'selected' : '') + '>IPv4 & IPv6</option>';
        const targetFields = [
            renderField('input', { id: 'edit-target-prefix', label: '域名前缀', hint: '留空表示根域。', value: target.prefix || '', placeholder: 'kr' }),
            renderField('input', { id: 'edit-target-min', label: '活跃数', hint: '最小可用数量。', value: String(target.minActive ?? 3), placeholder: '3', attrs: 'type="number" min="0"' }),
            renderField('input', { id: 'edit-target-country', label: '国家', hint: '可选，填写国家代码。', value: target.country || '', placeholder: '国家代码' }),
            renderField('input', { id: 'edit-target-asn', label: 'ASN', hint: '可选，填写 ASN 编号。', value: target.asn || '', placeholder: 'ASN编号' })
        ].join('');
        const targetContent = '<div class="config-edit-grid">'
            + renderField('select', { id: 'edit-target-zone', label: '权限配置', hint: '选择配置1/2/3。', className: 'form-select form-select-sm' }, getZoneOptionsHtml(target.zoneIndex ?? 0))
            + renderField('select', { id: 'edit-target-mode', label: '维护类型', hint: 'A/AAAA 或 TXT。', className: 'form-select form-select-sm', attrs: 'onchange="handleTargetModeChange()"' }, modeOptions)
            + renderField('select', { id: 'edit-target-exit', label: '出口类型', hint: '由检测 API 实时判断。', className: 'form-select form-select-sm' }, exitOptions)
            + targetFields
            + '<label class="field"><span>端口</span><small id="edit-target-port-hint">A/AAAA 模式使用，TXT 为任意。</small><input id="edit-target-port" class="form-control form-control-sm" value="' + escapeHTML(portValue) + '" data-a-port="' + escapeHTML(previousAPort) + '" placeholder="443"></label>'
            + '</div><input type="hidden" id="edit-target-enabled" value="' + (target.enabled !== false ? 'true' : 'false') + '">'
            + renderEditorActions('target', 'commitTargetEditor(' + index + ')');
        openConfigEditor('target', (index >= (configDraft?.targets || []).length ? '添加' : '编辑') + '管理域名', targetContent);
        syncTargetPortMode();
    }

    function syncTargetPortMode() {
        const mode = getInputValue('edit-target-mode') === 'TXT' ? 'TXT' : 'A';
        const portInput = byId('edit-target-port');
        const hint = byId('edit-target-port-hint');
        if (!portInput) return;
        if (mode === 'TXT') {
            if (!portInput.dataset.aPort || portInput.value !== '任意') {
                portInput.dataset.aPort = (portInput.value && portInput.value !== '任意') ? portInput.value : (portInput.dataset.aPort || '443');
            }
            portInput.value = '任意';
            portInput.disabled = true;
            if (hint) hint.textContent = 'TXT 模式不限制端口。';
        } else {
            portInput.disabled = false;
            portInput.value = portInput.dataset.aPort || (portInput.value === '任意' ? '443' : portInput.value) || '443';
            if (hint) hint.textContent = 'A/AAAA 模式使用。';
        }
    }

    function handleTargetModeChange() {
        const portInput = byId('edit-target-port');
        if (portInput && !portInput.disabled && portInput.value && portInput.value !== '任意') {
            portInput.dataset.aPort = portInput.value;
        }
        syncTargetPortMode();
    }

    function getTargetEditorValue() {
        const zoneIndex = parseInt(getInputValue('edit-target-zone') || '0', 10) || 0;
        const prefix = getInputValue('edit-target-prefix').replace(/^\\.+|\\.+$/g, '');
        const mode = getInputValue('edit-target-mode') === 'TXT' ? 'TXT' : 'A';
        const portInput = byId('edit-target-port');
        const port = mode === 'TXT' ? 'any' : ((portInput?.value || '').trim() || '443');
        const parsedMinActive = parseInt(getInputValue('edit-target-min'), 10);
        const minActive = Number.isFinite(parsedMinActive) ? Math.max(0, parsedMinActive) : (configDraft?.settings?.DEFAULT_MIN_ACTIVE ?? SETTINGS.DEFAULT_MIN_ACTIVE);
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

    function commitTargetEditor(index) {
        const target = getTargetEditorValue();
        if (!target.domain) {
            showToast('请先填写权限配置和域名前缀', 'error');
            return;
        }
        const targets = getDraftTargets();
        const nextTargets = targets.slice();
        nextTargets[index] = target;
        const duplicateMessage = getTargetDuplicateMessage(nextTargets);
        if (duplicateMessage) {
            showToast(duplicateMessage, 'error');
            return;
        }
        applyConfigDraftChange('targets', nextTargets, 'target', TARGET_SAVED_MSG);
    }

    function deleteTargetConfig(index) {
        if (!confirm('确认删除这个管理域名？')) return;
        const targets = getDraftTargets();
        targets.splice(index, 1);
        applyConfigDraftChange('targets', targets, 'target', TARGET_SAVED_MSG);
    }

    function toggleTargetEnabled(index, enabled) {
        const targets = getDraftTargets();
        if (!targets[index]) return;
        targets[index].enabled = enabled;
        configDraft.targets = targets;
        renderConfigCards();
        setConfigDirty(true, enabled ? '已开启该域名维护，点击“保存到 KV”后生效' : '已关闭该域名维护，点击“保存到 KV”后生效');
    }

    async function saveAppConfig() {
        const config = {
            zones: collectZoneConfigRows()
        };
        CONFIG_TEXT_FIELDS.forEach(([key, id]) => {
            config[key] = getInputValue(id);
        });
        CONFIG_TOGGLE_FIELDS.forEach(([key, id, fallback]) => {
            const el = byId(id);
            config[key] = el ? el.checked : fallback;
        });
        config.settings = {};
        CONFIG_NUMBER_FIELDS.forEach(([key, id]) => {
            config.settings[key] = getNumberInputValue(id, SETTINGS[key]);
        });
        config.targets = collectTargetConfigRows();
        const zoneDuplicateMessage = getZoneDuplicateMessage(config.zones);
        if (zoneDuplicateMessage) {
            showToast(zoneDuplicateMessage, 'error');
            return;
        }
        const targetDuplicateMessage = getTargetDuplicateMessage(config.targets);
        if (targetDuplicateMessage) {
            showToast(targetDuplicateMessage, 'error');
            return;
        }
        try {
            const btn = byId('btn-save-config');
            const cancelBtn = byId('btn-cancel-config');
            if (btn) {
                btn.disabled = true;
                btn.textContent = '保存中...';
            }
            if (cancelBtn) cancelBtn.disabled = true;
            const r = await apiPostJson('/api/save-config', { config });
            if (!r.success) {
                log(\`❌ 配置保存失败: \${r.error || '未知错误'}\`, 'error');
                showToast(r.error || '配置保存失败', 'error');
                return;
            }
            const savedConfig = cloneConfig(r.config || config);
            configDraft = savedConfig;
            configSavedSnapshot = cloneConfig(savedConfig);
            SETTINGS = configDraft.settings || SETTINGS;
            setConfigDirty(false);
            renderConfigCards();
            log('✅ 配置已保存到 KV，刷新页面后生效', 'success');
            showToast('配置已保存到 KV');
        } catch (e) {
            log(\`❌ 配置保存失败: \${e.message}\`, 'error');
            showToast('配置保存失败', 'error');
        } finally {
            const btn = byId('btn-save-config');
            const cancelBtn = byId('btn-cancel-config');
            if (btn) {
                btn.disabled = false;
                btn.textContent = '💾 保存到 KV';
            }
            if (cancelBtn) {
                cancelBtn.disabled = false;
            }
            setConfigDirty(configDirty);
        }
    }

    async function apiRequest(path, options = {}) {
        const opts = { ...options };
        const headers = new Headers(opts.headers || {});
        headers.set('Accept', 'application/json');
        if (opts.body && !(opts.body instanceof FormData) && !headers.has('Content-Type')) {
            headers.set('Content-Type', 'application/json');
        }
        opts.headers = headers;

        const resp = await fetch(path, opts);
        if (resp.status === 401 && AUTH_ENABLED) {
            location.href = '/';
        }
        return resp;
    }

    const apiJson = (path, options = {}) => apiRequest(path, options).then(r => r.json());
    const apiPostJson = (path, body = {}, options = {}) => apiJson(path, {
        ...options,
        method: 'POST',
        body: JSON.stringify(body)
    });
    const savePool = (poolKey, pool, mode = 'append') => apiPostJson('/api/save-pool', { pool, poolKey, mode });
    const restoreTrashIPs = ips => apiPostJson('/api/restore-from-trash', { ips, restoreToSource: true });

    function escapeHTML(str) {
        if (!str) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    function escapeJSString(str) {
        return JSON.stringify(String(str || '')).slice(1, -1).replace(/'/g, "\\'");
    }

    const log = (m, t='info', skipTimestamp=false) => {
        const w = byId('log-window');
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

    // ===== IP formatting / status table =====
    function normalizeIPFormat(input) {
        if (!input) return null;

        input = input.trim();
        const isValidIP = ip => ip.split('.').every(o => { const n = Number(o); return n >= 0 && n <= 255; });
        const isValidPort = port => { const n = Number(port); return n >= 1 && n <= 65535; };

        // 分离注释
        let comment = '';
        let mainPart = input;
        const commentIndex = input.indexOf('#');
        if (commentIndex > 0) {
            mainPart = input.substring(0, commentIndex).trim();
            comment = ' ' + input.substring(commentIndex).trim();
        }
        const fields = mainPart.split(',').map(item => item.trim());
        if (fields.length > 1) {
            const normalizedAddress = normalizeIPFormat(fields[0]);
            if (!normalizedAddress) return null;
            const metaFields = fields.slice(1, 4).map(item => item || 'null');
            return [normalizedAddress.split('#')[0].trim(), ...metaFields].join(',') + comment;
        }
        let match = mainPart.match(/^\\[([0-9a-fA-F:]+)\\]:(\\d+)$/);
        if (match && isValidPort(match[2])) {
            return \`[\${match[1]}]:\${match[2]}\${comment}\`;
        }
        if (/^[0-9a-fA-F:]+$/.test(mainPart) && mainPart.includes(':')) {
            return \`[\${mainPart.replace(/^\\[/, '').replace(/\\]$/, '')}]:443\${comment}\`;
        }

        // 已经是标准格式
        match = mainPart.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)$/);
        if (match && isValidIP(match[1]) && isValidPort(match[2])) {
            return \`\${match[1]}:\${match[2]}\${comment}\`;
        }

        // 空格分隔
        const parts = mainPart.split(/\\s+/);
        if (parts.length === 2) {
            const ip = parts[0].trim();
            const port = parts[1].trim();

            if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(ip) && /^\\d+$/.test(port) && isValidIP(ip) && isValidPort(port)) {
                return \`\${ip}:\${port}\${comment}\`;
            }
        }

        // 纯IP（默认443端口）
        if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(mainPart) && isValidIP(mainPart)) {
            return \`\${mainPart}:443\${comment}\`;
        }

        // 中文冒号
        match = mainPart.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})：(\\d+)$/);
        if (match && isValidIP(match[1]) && isValidPort(match[2])) {
            return \`\${match[1]}:\${match[2]}\${comment}\`;
        }

        const complexMatch = mainPart.match(/(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\D+(\\d+)/);
        if (complexMatch && isValidIP(complexMatch[1]) && isValidPort(complexMatch[2])) {
            return \`\${complexMatch[1]}:\${complexMatch[2]}\${comment}\`;
        }

        return null;
    }

    function formatIPInfo(ipInfo) {
        if (!ipInfo) return '';

        let html = '';
        if (ipInfo.country) {
            html += \`<span class="ip-info-tag" title="\${escapeHTML(ipInfo.country)}">\${escapeHTML(ipInfo.country)}</span>\`;
        }
        if (ipInfo.asn) {
            html += \`<span class="ip-info-tag" title="\${escapeHTML(formatAsn(ipInfo.asn))}">\${escapeHTML(formatAsn(ipInfo.asn))}</span>\`;
        }
        return html;
    }

    function formatAsn(asn) {
        const values = String(asn || '')
            .split(/[\/,\s]+/)
            .map(item => item.trim())
            .filter(item => item && !['null', 'unknown', 'n/a', '-', 'asnull', 'asunknown'].includes(item.toLowerCase()));
        if (!values.length) return '';
        return values.map(item => item.toUpperCase().startsWith('AS') ? item.toUpperCase() : 'AS' + item).join('/');
    }

    function formatExitInfo(exits) {
        if (!Array.isArray(exits) || exits.length === 0) return '';
        const ordered = [...exits].sort((a, b) => {
            const order = { ipv4: 0, v4: 0, ipv6: 1, v6: 1 };
            return (order[String(a.stack || '').toLowerCase()] ?? 9) - (order[String(b.stack || '').toLowerCase()] ?? 9);
        });
        return ordered.map(exit => {
            const stackValue = String(exit.stack || '').toLowerCase();
            const stack = exit.stack ? exit.stack.toUpperCase() : 'EXIT';
            const location = [exit.country, exit.city].filter(Boolean).join(' · ');
            const network = [formatAsn(exit.asn), exit.asOrganization].filter(Boolean).join(' · ');
            const dualClass = ['dual', 'v4/v6', 'dual-stack'].includes(stackValue) ? ' is-dual' : '';
            return \`<div class="exit-detail\${dualClass}">
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
            comment: raw.includes('#') ? raw.slice(raw.indexOf('#') + 1).trim() : ''
        };
    }

    function getPoolLineKey(line) {
        const source = normalizeIPFormat(line) || line;
        return parsePoolLine(source).address;
    }

    function getPoolKeySet(lines) {
        return new Set(lines.map(line => getPoolLineKey(line)).filter(Boolean));
    }

    function filterLinesByKeys(lines, keys, shouldMatch) {
        return lines.filter(line => {
            const key = getPoolLineKey(line);
            return key && (shouldMatch ? keys.has(key) : !keys.has(key));
        });
    }

    function buildPoolLineFromCheckResult(addr, result) {
        const parsed = parseAddrParts(addr);
        const ip = result.proxyIP || parsed.host;
        const port = result.portRemote || parsed.port;
        const asn = result.asn || (Array.isArray(result.exits) ? Array.from(new Set(result.exits.map(exit => exit.asn).filter(Boolean))).join('/') : '') || 'null';
        const country = result.country || (Array.isArray(result.exits) ? Array.from(new Set(result.exits.map(exit => exit.country).filter(Boolean))).join('/') : '') || 'null';
        const stack = result.stack || 'null';
        const host = String(ip || '').replace(/^\\[/, '').replace(/\\]$/, '');
        const address = host.includes(':') ? \`[\${host}]:\${port}\` : \`\${host}:\${port}\`;
        return \`\${address},\${formatAsn(asn) || 'null'},\${country || 'null'},\${stack || 'null'}\`;
    }

    function formatLatencyValue(value) {
        if (value === null || value === undefined || value === '' || value === '-') return '未知';
        const text = String(value).trim();
        return text.endsWith('ms') ? text : text + 'ms';
    }

    async function checkIPWithInfo(addr) {
        const r = await apiJson(\`/api/check-ip?ip=\${encodeURIComponent(addr)}\`);
        return { ip: addr, success: r.success, colo: r.colo || 'N/A', time: r.responseTime || '-', exits: r.exits || [], proxyIP: r.proxyIP, portRemote: r.portRemote, ipInfo: r.ipInfo || null, asn: r.asn, country: r.country, stack: r.stack };
    }

    const addProbeButton = r => \`<button class="btn btn-sm btn-outline-primary" onclick="addToInput('\${escapeHTML(buildPoolLineFromCheckResult(r.ip, r))}')" title="添加到输入框">➕</button>\`;

    function renderIPRow(r, actionHTML) {
        const infoHtml = formatExitInfo(r.exits) || (r.ipInfo ? formatIPInfo(r.ipInfo) : '-');
        return \`<tr>
            <td><span class="pill-badge address-pill copyable" onclick="copyText('\${escapeJSString(r.ip)}', '维护地址')" title="点击复制">\${escapeHTML(r.ip)}</span></td>
            <td><span class="colo-badge" title="Cloudflare 机房 / colo">\${escapeHTML(r.colo || 'N/A')}</span></td>
            <td><span class="latency-badge" title="来自后端检测 API 返回的 responseTime，不是浏览器到节点的延迟">\${escapeHTML(formatLatencyValue(r.time))}</span></td>
            <td><span class="status-badge \${r.success?'ok':'bad'}">\${r.success?'可用':'失败'}</span></td>
            <td class="exit-list-cell">\${infoHtml}</td>
            <td>\${actionHTML}</td>
        </tr>\`;
    }

    async function renderProbeResults(targets, total = targets.length) {
        const checkResults = await Promise.all(targets.map(addr => checkIPWithInfo(addr)));
        byId('status-table').innerHTML = checkResults.map(r => renderIPRow(r, addProbeButton(r))).join('');
        const activeCount = checkResults.filter(r => r.success).length;
        log(\`📊 探测完成: \${activeCount}/\${total} 活跃\`, activeCount === total ? 'success' : (activeCount > 0 ? 'warn' : 'error'));
    }

    function switchDomain() {
        if (!TARGETS.length) {
            const manualSection = byId('manual-add-section');
            const t = byId('status-table');
            const summary = byId('current-target-summary-content');
            if (manualSection) manualSection.hidden = true;
            if (summary) summary.innerHTML = renderTargetSummary();
            if (t) t.innerHTML = '<tr><td colspan="6" class="text-secondary p-4">请先到配置中心添加管理域名</td></tr>';
            log('请先在配置中心添加管理域名', 'warn');
            return;
        }
        currentTargetIndex = parseInt(byId('domain-select').value);
        const target = TARGETS[currentTargetIndex];
        const summary = byId('current-target-summary-content');
        if (summary) summary.innerHTML = renderTargetSummary(target);
        log(\`切换到: \${target.domain} (\${target.mode})\`);

        const manualSection = byId('manual-add-section');
        if (manualSection) manualSection.hidden = false;

        refreshStatus();
    }

    // ===== Pool editor actions =====
    async function loadRemoteUrl() {
        const url = byId('remote-url').value.trim();
        if (!url) {
            log('❌ 请输入URL', 'error');
            return;
        }

        log(\`🌐 加载: \${url}\`, 'warn');
        try {
            const r = await apiPostJson('/api/load-remote-url', { url });

            if (r.success) {
                setInputValueAndPreview('ip-input', r.ips);
                log(\`✅ 成功: \${r.count} 个\`, 'success');
            } else {
                log(\`❌ 失败\`, 'error');
            }
        } catch (e) {
            log(\`❌ 出错\`, 'error');
        }
    }

    function setPoolCount(count) {
        byId('pool-count').innerText = count;
    }

    function clearPoolInput() {
        setInputValueAndPreview('ip-input', '');
    }

    const fetchCurrentPool = () => apiJson('/api/get-pool?poolKey=' + currentPool);

    async function loadCurrentPool() {
        log(\`📂 加载 \${currentPool}...\`, 'info');

        try {
            const r = await fetchCurrentPool();
            setElementValue('ip-input', r.pool);
            setPoolCount(r.count);
            updateFilterPreview();
            log(\`✅ 已加载 \${r.count} 个IP\`, 'success');
        } catch (e) {
            log('❌ 加载失败', 'error');
        }
    }

    async function saveToCurrentPool(mode = 'append') {
        const content = byId('ip-input').value;
        if (!content.trim()) {
            log('❌ 内容为空', 'error');
            return;
        }

        const modeLabel = mode === 'replace' ? '覆盖' : '追加';
        log(\`💾 \${modeLabel}到 \${getPoolName(currentPool)}...\`, 'warn');

        try {
            const r = await savePool(currentPool, content, mode);

            if (r.success) {
                if (mode === 'replace') {
                    log(\`✅ \${r.message}\`, 'success');
                } else {
                    log(\`✅ 已追加 \${r.added} 个IP到 \${getPoolName(currentPool)}\`, 'success');
                }
                setPoolCount(r.count);
                clearPoolInput();
            } else {
                log(\`❌ 失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 保存失败\`, 'error');
        }
    }

    async function removeFromPool() {
        const content = byId('ip-input').value;
        if (!content.trim()) {
            log('❌ 内容为空', 'error');
            return;
        }

        if (!confirm(\`确认从 \${getPoolName(currentPool)} 中删除这些IP？\`)) return;

        log(\`🗑️ 从 \${getPoolName(currentPool)} 删除...\`, 'warn');

        try {
            const r = await savePool(currentPool, content, 'remove');

            if (r.success) {
                log(\`✅ \${r.message}\`, 'success');
                setPoolCount(r.count);
                clearPoolInput();
            } else {
                log(\`❌ 失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 删除失败\`, 'error');
        }
    }

    async function showPoolInfo() {
        try {
            const r = await fetchCurrentPool();
            setPoolCount(r.count);
        } catch (e) {
            log('❌ 查询失败', 'error');
        }
    }

    async function batchCheck() {
        const btn = byId('btn-check');
        const input = byId('ip-input');
        const lines = getInputLines('ip-input');

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
            byId('pg-bar').style.width = '0%';
            return 'abandoned';
        }

        abortController = new AbortController();
        const signal = abortController.signal;

        btn.textContent = '🛑 停止检测';
        btn.classList.remove('btn-warning');
        btn.classList.add('btn-danger');

        let valid = [], total = lines.length, checked = 0;
        const pg = byId('pg-bar');
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
                            const data = await apiJson(\`/api/lookup-domain?domain=\${encodeURIComponent(domain + ':' + port)}\`);
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
                        checkTargets = [getPoolLineKey(normalized)];
                    }

                    // 检测所有目标IP
                    for (const checkTarget of checkTargets) {
                        try {
                            const checkUrl = \`/api/check-ip?ip=\${encodeURIComponent(checkTarget)}\`;
                            const r = await apiJson(checkUrl, {
                                signal: signal
                            });

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
        const input = byId('ip-input');
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

        const input = byId('ip-input');
        // 将有效IP和未检测IP合并
        const newContent = [...pausedCheckState.validIPs, ...pausedCheckState.uncheckedLines].join('\\n');
        input.value = newContent;
        updateFilterPreview();

        log(\`🔄 继续检测剩余 \${pausedCheckState.uncheckedLines.length} 个IP\`, 'info');

        pausedCheckState = null;

        // 继续检测
        return await batchCheck();
    }

    // 放弃检测
    function abandonCheck() {
        if (pausedCheckState && pausedCheckState.validIPs.length > 0) {
            const input = byId('ip-input');
            input.value = pausedCheckState.validIPs.join('\\n');
            updateFilterPreview();
            log(\`🚫 已放弃检测，保留 \${pausedCheckState.validIPs.length} 个有效IP在输入框\`, 'warn');
        } else {
            log(\`🚫 已放弃检测\`, 'warn');
        }

        pausedCheckState = null;
    }

    function quickDeduplicate() {
        const input = byId('ip-input');
        const lines = getInputLines('ip-input');

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
                const key = getPoolLineKey(normalized);
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

    // ===== Domain status / lookup / maintenance actions =====
    async function refreshStatus() {
        const t = byId('status-table');
        const txtDiv = byId('txt-status');
            const colspan = '6';
        if (!TARGETS.length) {
            t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">请先到配置中心添加管理域名</td></tr>\`;
            txtDiv.innerHTML = '';
            return;
        }
        t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">🔄 查询中...</td></tr>\`;
        txtDiv.innerHTML = '';

        try {
            const data = await apiJson(\`/api/current-status?target=\${currentTargetIndex}\`);

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
        if (!TARGETS.length) {
            log('❌ 请先添加管理域名', 'error');
            return;
        }
        const input = byId('manual-add-ip');
        const ip = input.value.trim();

        if (!ip) {
            log('❌ 请输入IP', 'error');
            return;
        }

        const target = TARGETS[currentTargetIndex];

        log(\`➕ 添加到\${MODE_LABELS[target.mode]}: \${ip}\`, 'info');

        try {
            const r = await apiPostJson('/api/add-a-record', { ip, targetIndex: currentTargetIndex });

            if (r.success) {
                const mode = r.mode || 'A';
                log(\`✅ 成功添加到\${mode}记录\`, 'success');
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
        const input = byId('lookup-domain');
        const val = input.value.trim();

        if (!val) {
            log('❌ 请输入', 'error');
            return;
        }

        log(\`🔍 探测: \${val}\`, 'info');

        const t = byId('status-table');
        const txtDiv = byId('txt-status');
        const colspan = '6';
        t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">🔄 探测中...</td></tr>\`;
        txtDiv.innerHTML = '';

        try {
            if (val.startsWith('txt@')) {
                const data = await apiJson(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`);

                // null 检查
                if (!data.ips || !Array.isArray(data.ips)) {
                    log(\`❌ TXT 查询失败\`, 'error');
                    t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ TXT 查询失败</td></tr>\`;
                    return;
                }

                log(\`📝 TXT: \${data.ips.length} 个IP\`, 'success');
                await renderProbeResults(data.ips);
                return;
            }

            const isIP = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?$/.test(val) || /^\\[[0-9a-fA-F:]+\\](:\\d+)?$/.test(val) || (/^[0-9a-fA-F:]+$/.test(val) && val.includes(':'));
            let targets = [];

            if (isIP) {
                const normalized = normalizeIPFormat(val);
                targets = [normalized ? getPoolLineKey(normalized) : val];
            } else {
                const data = await apiJson(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`);

                if (!data.ips || !Array.isArray(data.ips) || data.ips.length === 0) {
                    log(\`⚠️ 域名无A/AAAA记录\`, 'warn');
                    t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">域名无A/AAAA记录</td></tr>\`;
                    return;
                }

                targets = data.ips.map(ip => ip.includes(':') ? \`[\${ip.replace(/^\\[/, '').replace(/\\]$/, '')}]:\${data.port || '443'}\` : \`\${ip}:\${data.port || '443'}\`);
                log(\`📡 \${data.ips.length} 个IP (端口: \${data.port || '443'})\`, 'success');
            }

            await renderProbeResults(targets);
        } catch (e) {
            log(\`❌ 失败: \${e.message}\`, 'error');
            t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ 探测失败</td></tr>\`;
        }
    }

    function addToInput(ip) {
        const input = byId('ip-input');
        const lines = getInputLines('ip-input');

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
            await apiRequest('/api/delete-record?id=' + encodeURIComponent(id) + '&target=' + currentTargetIndex, { method: 'POST' });
            log('🗑️  已删除', 'success');
            refreshStatus();
        } catch (e) {
            log('❌ 失败', 'error');
        }
    }

    async function deleteTxtIP(recordId, ip) {
        if (!confirm('确认删除 ' + ip + '？')) return;

        try {
            await apiRequest('/api/delete-record?id=' + encodeURIComponent(recordId) + '&ip=' + encodeURIComponent(ip) + '&isTxt=true&target=' + currentTargetIndex, { method: 'POST' });
            log('🗑️ 已从TXT记录删除', 'success');
            refreshStatus();
        } catch (e) {
            log('❌ 删除失败', 'error');
        }
    }

    async function runMaintain() {
        log('🔧 启动维护...', 'warn');

        try {
            const r = await apiJson('/api/maintain?manual=true', { method: 'POST' });

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

    // ===== Pool mapping / trash / filtering =====
    async function loadDomainPoolMapping() {
        try {
            const r = await apiJson('/api/get-domain-pool-mapping');
            applyPoolState(r);
            log('✅ 已加载池配置', 'success');
        } catch (e) {
            log('❌ 加载配置失败', 'error');
        }
    }

    function updatePoolSelector() {
        const selector = byId('pool-selector');
        if (!selector) return;
        const pools = [...new Set([POOL_DEFAULT_KEY, POOL_TRASH_KEY, ...(Array.isArray(availablePools) ? availablePools : [])])]
            .sort(comparePoolKeys);

        selector.innerHTML = pools.map(pool => \`<option value="\${escapeHTML(pool)}">\${escapeHTML(getPoolName(pool))}</option>\`).join('');
        selector.value = currentPool;
    }

    function updateDomainBindingTable() {
        const tbody = byId('domain-binding-list');
        if (!tbody) return;
        if (TARGETS.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" class="text-center text-secondary">请先到配置中心添加管理域名</td></tr>';
            return;
        }

        tbody.innerHTML = TARGETS.map(target => {
            const bindingKey = getTargetDuplicateKey(target);
            const boundPool = getBoundPoolForTarget(target);
            const mode = target.mode === 'TXT' ? 'TXT' : 'A';
            const modeLabel = MODE_LABELS[mode] || mode;
            const modeShortLabel = mode === 'TXT' ? 'T' : 'A';
            const badgeClass = 'record-badge-' + mode.toLowerCase();

            const selectablePools = (Array.isArray(availablePools) ? availablePools : [POOL_DEFAULT_KEY])
                .filter(p => p !== POOL_TRASH_KEY);

            const options = selectablePools.map(pool => {
                const selected = pool === boundPool ? 'selected' : '';
                return \`<option value="\${escapeHTML(pool)}" \${selected}>\${escapeHTML(getPoolName(pool))}</option>\`;
            }).join('');

            return \`
                <tr>
                    <td>
                        <span class="domain-binding-domain" title="\${escapeHTML(target.domain || '')}">
                            <span class="record-badge \${badgeClass}" title="\${escapeHTML(modeLabel)}">\${escapeHTML(modeShortLabel)}</span>
                            <span class="domain-binding-name">\${escapeHTML(target.domain || '')}</span>
                        </span>
                    </td>
                    <td>
                        <select class="form-select form-select-sm domain-binding-select"
                                onchange="bindDomainToPool('\${escapeJSString(bindingKey)}', this.value)">
                            \${options}
                        </select>
                    </td>
                </tr>
            \`;
        }).join('');
    }

    function promptPoolName(message, initialValue = '') {
        const name = prompt(message, initialValue);
        if (!name) return '';
        const displayName = name.trim();
        if (!displayName) {
            alert('显示名称不能为空!');
            return '';
        }
        return displayName;
    }

    async function submitPoolStateChange(request, { successMessage, errorMessage, applyResult, onLogicalFailure } = {}) {
        try {
            const result = typeof request === 'function' ? await request() : await request;
            if (!result.success) {
                if (onLogicalFailure) onLogicalFailure(result);
                else log(errorMessage + ': ' + (result.error || '未知错误'), 'error');
                return false;
            }
            if (applyResult) applyResult(result);
            log(typeof successMessage === 'function' ? successMessage(result) : successMessage, 'success');
            return true;
        } catch (e) {
            log(errorMessage, 'error');
            return false;
        }
    }

    async function createNewPool() {
        const displayName = promptPoolName('输入池显示名称');
        if (!displayName) return;

        await submitPoolStateChange(
            () => apiPostJson('/api/create-pool', { displayName }),
            {
                successMessage: r => '✅ 已创建池: ' + getPoolName(r.poolKey),
                errorMessage: '❌ 创建池失败',
                applyResult: r => {
                    currentPool = r.poolKey;
                    applyPoolState(r);
                },
                onLogicalFailure: r => alert(r.error || '创建失败')
            }
        );
    }

    async function renameCurrentPool() {
        if (currentPool === POOL_TRASH_KEY) {
            alert(\`不能重命名\${getPoolName(currentPool)}!\`);
            return;
        }

        const displayName = promptPoolName('输入新的池显示名称', getPoolName(currentPool));
        if (!displayName) return;

        await submitPoolStateChange(
            () => apiPostJson('/api/rename-pool', { poolKey: currentPool, displayName }),
            {
                successMessage: '✅ 已重命名为: ' + displayName,
                errorMessage: '❌ 重命名失败',
                applyResult: r => {
                    applyPoolState(r);
                    showToast('池名称已更新');
                }
            }
        );
    }

    async function deleteCurrentPool() {
        const protectedPools = [POOL_DEFAULT_KEY, POOL_TRASH_KEY];
        if (protectedPools.includes(currentPool)) {
            alert(\`不能删除\${getPoolName(currentPool)}!\`);
            return;
        }

        const boundDomains = Object.entries(domainPoolMapping)
            .filter(([, poolKey]) => poolKey === currentPool)
            .map(([domain]) => domain);
        const confirmLines = [
            \`确认删除 \${getPoolFixedName(currentPool)}（\${getPoolName(currentPool)}）？\`
        ];
        if (boundDomains.length) {
            confirmLines.push('', \`当前有 \${boundDomains.length} 个管理域名绑定到该池，删除后会自动改回默认池。\`);
            confirmLines.push(...boundDomains.slice(0, 5).map(domain => \`- \${domain}\`));
            if (boundDomains.length > 5) confirmLines.push(\`...还有 \${boundDomains.length - 5} 个\`);
        }
        if (!confirm(confirmLines.join('\\n'))) return;

        await submitPoolStateChange(
            () => apiJson('/api/delete-pool?poolKey=' + currentPool, { method: 'POST' }),
            {
                successMessage: '✅ 已删除池',
                errorMessage: '❌ 删除失败',
                applyResult: r => {
                    currentPool = POOL_DEFAULT_KEY;
                    applyPoolState(r);
                }
            }
        );
    }

    function switchPool() {
        currentPool = byId('pool-selector').value;
        log(\`📦 切换到: \${getPoolName(currentPool)}\`, 'info');

        const trashActions = byId('trash-actions');
        if (trashActions) trashActions.hidden = currentPool !== POOL_TRASH_KEY;

        showPoolInfo();
    }

    function rollbackDomainPoolMapping(mapping) {
        domainPoolMapping = mapping;
        updateDomainBindingTable();
    }

    async function bindDomainToPool(bindingKey, poolKey) {
        const target = TARGETS.find(item => getTargetDuplicateKey(item) === bindingKey);
        const mode = target?.mode === 'TXT' ? 'TXT' : 'A';
        const modeLabel = target ? (MODE_LABELS[mode] || mode) : '';
        const domain = target ? target.domain + ' (' + modeLabel + ')' : bindingKey;
        const oldPool = target ? getBoundPoolForTarget(target) : (domainPoolMapping[bindingKey] || POOL_DEFAULT_KEY);
        if (oldPool === poolKey) return;
        const oldMapping = { ...domainPoolMapping };
        const oldName = getPoolName(oldPool);
        const newName = getPoolName(poolKey);
        const message = [
            \`确认切换 \${domain} 的绑定池？\`,
            \`\`,
            \`当前：\${oldName}（\${getPoolFixedName(oldPool)}）\`,
            \`切换到：\${newName}（\${getPoolFixedName(poolKey)}）\`,
            \`\`,
            \`切换后下一次维护会从新池补充 IP。\`
        ].join('\\n');
        if (!confirm(message)) {
            updateDomainBindingTable();
            return;
        }
        domainPoolMapping[bindingKey] = poolKey;

        try {
            const r = await apiPostJson('/api/save-domain-pool-mapping', { mapping: domainPoolMapping });
            if (!r.success) {
                rollbackDomainPoolMapping(oldMapping);
                log(\`❌ 绑定失败: \${r.error || '未知错误'}\`, 'error');
                return;
            }
            applyPoolState(r);

            log(\`✅ \${domain} → \${getPoolName(poolKey)}\`, 'success');
        } catch (e) {
            rollbackDomainPoolMapping(oldMapping);
            log('❌ 绑定失败', 'error');
        }
    }

    async function clearTrash() {
        if (!confirm('确认清空垃圾桶？此操作不可恢复！')) return;

        await submitPoolStateChange(
            () => apiJson('/api/clear-trash', { method: 'POST' }),
            {
                successMessage: '✅ 垃圾桶已清空',
                errorMessage: '❌ 清空失败',
                applyResult: () => {
                    loadCurrentPool();
                }
            }
        );
    }

    // 一键洗库状态
    let cleaningPool = null;

    // 一键洗库：加载池 → 检测 → 自动保存
    // 普通池：有效IP覆盖保存，失效IP移入垃圾桶
    // 垃圾桶：有效IP恢复到原来的库
    async function oneClickClean() {
        const isTrash = currentPool === POOL_TRASH_KEY;

        log(\`🧹 开始一键洗库: \${getPoolName(currentPool)}\`, 'warn');
        cleaningPool = currentPool;

        // 1. 加载池
        let allIPs = [];
        let originalLines = []; // 保存原始行（包含注释）
        try {
            const r = await apiJson(\`/api/get-pool?poolKey=\${currentPool}\`);
            if (!r.pool || !r.pool.trim()) {
                log('❌ 池为空，无需清洗', 'error');
                cleaningPool = null;
                return;
            }
            originalLines = nonEmptyLines(r.pool);
            allIPs = [...originalLines];
            setInputValueAndPreview('ip-input', r.pool);
            log(\`📂 已加载 \${r.count} 个IP\`, 'info');
        } catch (e) {
            log('❌ 加载失败', 'error');
            cleaningPool = null;
            return;
        }

        // 2. 检测（等待检测完成或中断）
        const checkResult = await batchCheck();

        // 3. 只有完全检测完成才自动保存，中断或放弃则不保存
        const content = byId('ip-input').value;
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
    }

    // 普通池洗库结果保存：有效IP覆盖保存，失效IP移入垃圾桶
    async function savePoolCleanResult(validLines, originalLines) {
        const validCount = validLines.length;

        const validKeys = getPoolKeySet(validLines);
        const invalidLines = filterLinesByKeys(originalLines, validKeys, false);

        try {
            // 1. 保存有效IP到池（覆盖）
            if (validCount > 0) {
                const r = await savePool(cleaningPool, validLines.join('\\n'), 'replace');

                if (r.success) {
                    log(\`✅ 洗库完成: \${r.message}\`, 'success');
                    setPoolCount(r.count);
                } else {
                    log(\`❌ 保存失败: \${r.error}\`, 'error');
                    return;
                }
            } else {
                // 清空池
                await savePool(cleaningPool, '', 'replace');
                log(\`⚠️ 洗库完成，无有效IP，池已清空\`, 'warn');
                setPoolCount('0');
            }

            // 2. 失效IP移入垃圾桶
            if (invalidLines.length > 0) {
                const trashContent = invalidLines.map(line => {
                    const key = getPoolLineKey(line);
                    return \`\${key} # 洗库失效 \${new Date().toISOString()} 来自 \${cleaningPool}\`;
                }).join('\\n');

                await savePool(POOL_TRASH_KEY, trashContent, 'append');

                log(\`🗑️ 已将 \${invalidLines.length} 个失效IP移入垃圾桶\`, 'info');
            }

            clearPoolInput();
        } catch (e) {
            log(\`❌ 保存失败\`, 'error');
        }
    }

    // 垃圾桶洗库结果保存：有效IP恢复到原来的库
    async function saveTrashCleanResult(validLines, originalLines) {
        if (validLines.length === 0) {
            log(\`⚠️ 洗库完成，无有效IP可恢复\`, 'warn');
            clearPoolInput();
            return;
        }

        const validKeys = getPoolKeySet(validLines);
        const ipsToRestore = filterLinesByKeys(originalLines, validKeys, true).map(getPoolLineKey);

        try {
            const r = await restoreTrashIPs(ipsToRestore);

            if (r.success) {
                log(\`✅ 垃圾桶洗库完成: \${r.message}\`, 'success');
                logRestoreSummary(r);
                clearPoolInput();
                showPoolInfo();
            } else {
                log(\`❌ 恢复失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 恢复失败\`, 'error');
        }
    }

    function logRestoreFailure(message = '恢复失败') {
        log('❌ ' + message, 'error');
    }

    async function restoreSelected() {
        const lines = getInputLines('ip-input');

        if (lines.length === 0) {
            log('❌ 请先选择要恢复的IP', 'error');
            return;
        }

        const ips = lines.map(line => getPoolLineKey(line)).filter(Boolean);

        try {
            const r = await restoreTrashIPs(ips);

            if (r.success) {
                handleRestoreSuccess(r, true);
            } else {
                logRestoreFailure(r.error);
            }
        } catch (e) {
            logRestoreFailure();
        }
    }

    function handleRestoreSuccess(result, reloadPool = false) {
        log('✅ ' + result.message, 'success');
        logRestoreSummary(result);
        if (reloadPool) loadCurrentPool();
        else {
            clearPoolInput();
            showPoolInfo();
        }
    }

    function logRestoreSummary(result) {
        const entries = Array.isArray(result.restoredByPoolDisplay) ? result.restoredByPoolDisplay : [];
        if (entries.length <= 1) return;
        entries.forEach(item => {
            log(\`   \${item.label || item.name}: \${item.count} 个\`, 'info');
        });
    }

    function smartFilter(mode) {
        const input = byId('ip-input');
        const criteria = parseFilterExpression(getInputValue('universal-filter'));

        if (!criteria) {
            log('❌ 请至少填写一个筛选条件', 'error');
            return;
        }

        const lines = getInputLines('ip-input');
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
        const asnValues = String(meta.asn || '').replace(/AS/gi, '').toUpperCase().split(/[\/,\s]+/).filter(Boolean);
        if (criteria.asns.length && !criteria.asns.some(asn => asnValues.includes(asn))) return false;
        if (criteria.text.length && !criteria.text.some(token => searchable.includes(token))) return false;
        return true;
    }

    function updateFilterPreview() {
        const preview = byId('filter-preview');
        if (!preview) return;
        const lines = getInputLines('ip-input');
        const criteria = parseFilterExpression(getInputValue('universal-filter'));
        if (!criteria) {
            preview.innerHTML = '输入条件后会显示匹配数量。';
            return;
        }
        const matched = lines.filter(line => lineMatchesUniversalFilter(line, criteria)).length;
        preview.innerHTML = \`当前输入 <strong>\${lines.length}</strong> 条，匹配 <strong>\${matched}</strong> 条。\`;
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
        const configBody = document.querySelector('.config-details-body');
        ['input', 'change'].forEach(type => configBody?.addEventListener(type, () => setConfigDirty(true, type === 'change' ? '基础配置已保存到页面，点击“保存到 KV”后生效' : '')));
        ['ip-input', 'universal-filter'].forEach(id => {
            const el = byId(id);
            if (el) el.addEventListener('input', updateFilterPreview);
        });
        updateFilterPreview();
        switchDomain();
        Promise.all([
            showPoolInfo(),
            loadDomainPoolMapping()
        ]).catch(e => log('⚠️ 初始化部分失败', 'error'));
    });
</script>`;
}

function renderHTML(C, runtimeState = {}) {
    const targetsJson = JSON.stringify(C.targets);
    const settingsJson = JSON.stringify(getRuntimeSettings(C));
    const appConfigJson = JSON.stringify(getEditableConfig(C));
    const kvReady = runtimeState.kvReady !== false;
    const version = APP_VERSION;

    // The Worker is intentionally single-file deployable. Keep front-end code
    // grouped by the anchors below instead of extracting external assets.
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro - IP管理面板</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🌐</text></svg>">
    ${renderAppStyles()}
</head>
<body class="pb-5">

${renderGithubCorner()}

${renderHero(C, kvReady)}

<div class="container">
    ${renderTopNav()}

    ${renderDashboardPage()}

    ${renderConfigPage()}
</div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>

${renderClientScript({ targetsJson, settingsJson, appConfigJson, authEnabled: !!C.authKey })}
<footer class="container text-center text-secondary small py-3">DDNS Pro · ${version}</footer>
</body>
</html>`;
    // 压缩HTML空白，减少传输体积约20-30%
    return html
        .replace(/^[ \t]+/gm, '')
        .replace(/\n{2,}/g, '\n');
}
