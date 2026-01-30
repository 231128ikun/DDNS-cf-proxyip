/**
 * DDNS Pro & Proxy IP Manager v5.3
 */

// ========== 运行时配置 ==========
let CONFIG = {
    email: '',
    apiKey: '',
    zoneId: '',
    targets: [],
    tgToken: '',
    tgId: '',
    checkApi: '',
    dohApi: '',
    projectUrl: '',
    ipInfoEnabled: false,
    ipInfoApi: ''
};

// ========== 全局设置 ==========
const GLOBAL_SETTINGS = {
    CONCURRENT_CHECKS: 10,       // 并发数：10（网络好可改为15-20）
    CHECK_TIMEOUT: 6000,         // 超时：6秒
    REMOTE_LOAD_TIMEOUT: 10000,  // 远程加载超时：10秒
    IP_INFO_TIMEOUT: 6000,       // ip归属地查询超时：6秒
};

// ========== 工具函数 ==========
function safeJSONParse(str, defaultValue = null) {
    try {
        return str ? JSON.parse(str) : defaultValue;
    } catch (e) {
        console.error('JSON解析失败:', e.message);
        return defaultValue;
    }
}

function formatLogMessage(message, type = 'info') {
    const time = new Date().toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' });
    return `[${time}] ${message}`;
}

// ========== Worker主入口 ==========
export default {
    async fetch(request, env, ctx) {
        const requestStart = Date.now();
        initConfig(env, request);
        const url = new URL(request.url);

        if (url.pathname === '/') {
            const html = renderHTML(CONFIG);
            console.log(`📄 首页请求处理耗时: ${Date.now() - requestStart}ms`);
            return new Response(html, {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }

        if (url.pathname === '/favicon.ico') {
            return new Response(null, { status: 204 });
        }

        try {
            const apiStart = Date.now();
            const response = await handleAPIRequest(url, request, env);
            console.log(`🔧 API请求 ${url.pathname} 处理耗时: ${Date.now() - apiStart}ms`);
            
            // 添加性能头信息（移除缓存统计）
            const headers = new Headers(response.headers);
            headers.set('X-Processing-Time', `${Date.now() - requestStart}ms`);
            
            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers
            });
        } catch (e) {
            console.error(`❌ 请求处理失败 ${url.pathname}:`, e);
            return new Response(JSON.stringify({ 
                error: '内部服务器错误',
                message: '请稍后重试'
            }), { 
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },

    async scheduled(event, env, ctx) {
        console.log('⏰ 定时任务开始执行');
        const startTime = Date.now();
        
        try {
            initConfig(env);
            ctx.waitUntil((async () => {
                await maintainAllDomains(env, false);
                console.log(`✅ 定时任务完成，总耗时: ${Date.now() - startTime}ms`);
            })());
        } catch (e) {
            console.error('❌ 定时任务失败:', e);
        }
    }
};

// ========== API请求处理器 ==========
async function handleAPIRequest(url, request, env) {
    const pathname = url.pathname;
    
    // 获取IP池
    if (pathname === '/api/get-pool') {
        return await handleGetPool(url, env);
    }
    
    // 保存IP池
    if (pathname === '/api/save-pool') {
        return await handleSavePool(request, env);
    }
    
    // 从远程URL加载IP
    if (pathname === '/api/load-remote-url') {
        return await handleLoadRemoteUrl(request);
    }
    
    // 获取当前解析状态
    if (pathname === '/api/current-status') {
        return await handleCurrentStatus(url);
    }
    
    // 查询域名解析
    if (pathname === '/api/lookup-domain') {
        return await handleLookupDomain(url);
    }
    
    // 检测单个IP
    if (pathname === '/api/check-ip') {
        return await handleCheckIP(url);
    }
    
    // 查询IP归属地信息
    if (pathname === '/api/ip-info') {
        return await handleIPInfo(url);
    }
    
    // 删除DNS记录
    if (pathname === '/api/delete-record') {
        return await handleDeleteRecord(url);
    }
    
    // 添加A记录
    if (pathname === '/api/add-a-record') {
        return await handleAddARecord(request);
    }
    
    // 执行维护任务
    if (pathname === '/api/maintain') {
        return await handleMaintain(url, env);
    }
    
    // 获取域名与池的映射关系
    if (pathname === '/api/get-domain-pool-mapping') {
        return await handleGetDomainPoolMapping(env);
    }
    
    // 保存域名与池的映射关系
    if (pathname === '/api/save-domain-pool-mapping') {
        return await handleSaveDomainPoolMapping(request, env);
    }
    
    // 创建新池
    if (pathname === '/api/create-pool') {
        return await handleCreatePool(request, env);
    }
    
    // 删除池
    if (pathname === '/api/delete-pool') {
        return await handleDeletePool(url, env);
    }
    
    return new Response('Not Found', { status: 404 });
}

// ========== API处理函数 ==========
async function handleGetPool(url, env) {
    const poolKey = url.searchParams.get('poolKey') || 'pool';
    const onlyCount = url.searchParams.get('onlyCount') === 'true';
    
    const pool = await env.IP_DATA.get(poolKey) || '';
    const count = pool.trim() ? pool.trim().split('\n').length : 0;
    
    if (onlyCount) {
        return new Response(JSON.stringify({ count }));
    }
    return new Response(JSON.stringify({ pool, count }));
}

async function handleSavePool(request, env) {
    const body = await request.json();
    const poolKey = body.poolKey || 'pool';
    const newIPs = await cleanIPListAsync(body.pool || '');
    
    if (!newIPs) {
        return new Response(JSON.stringify({ success: false, error: '没有有效IP' }), { status: 400 });
    }
    
    const existingPool = await env.IP_DATA.get(poolKey) || '';
    const existingSet = new Set(existingPool.split('\n').filter(l => l.trim()));
    
    newIPs.split('\n').forEach(ip => {
        if (ip.trim()) existingSet.add(ip.trim());
    });
    
    const finalPool = Array.from(existingSet).join('\n');
    await env.IP_DATA.put(poolKey, finalPool);
    
    return new Response(JSON.stringify({
        success: true,
        count: existingSet.size,
        added: existingSet.size - (existingPool ? existingPool.split('\n').filter(l => l.trim()).length : 0)
    }));
}

async function handleLoadRemoteUrl(request) {
    const body = await request.json();
    const url = body.url;
    if (!url) {
        return new Response(JSON.stringify({ success: false, error: '缺少URL' }), { status: 400 });
    }
    const ips = await loadFromRemoteUrl(url);
    return new Response(JSON.stringify({ 
        success: true, 
        ips,
        count: ips ? ips.split('\n').length : 0
    }));
}

async function handleCurrentStatus(url) {
    const targetIndex = parseInt(url.searchParams.get('target') || '0');
    const target = CONFIG.targets[targetIndex];
    if (!target) {
        return new Response(JSON.stringify({ error: '无效的目标' }), { status: 400 });
    }
    const status = await getDomainStatus(target);
    return new Response(JSON.stringify(status));
}

async function handleLookupDomain(url) {
    const input = url.searchParams.get('domain');
    
    if (input.startsWith('txt@')) {
        const domain = input.substring(4);
        const txtData = await resolveTXTRecord(domain);
        return new Response(JSON.stringify({ 
            type: 'TXT',
            domain,
            ips: txtData.ips,
            raw: txtData.raw
        }));
    }
    
    const { domain, port } = parseDomainPort(input);
    const ips = await resolveDomain(domain);
    return new Response(JSON.stringify({ 
        type: 'A',
        ips, 
        port, 
        domain 
    }));
}

async function handleCheckIP(url) {
    const target = url.searchParams.get('ip');
    const res = await checkProxyIP(target);
    return new Response(JSON.stringify(res));
}

async function handleIPInfo(url) {
    const ip = url.searchParams.get('ip');
    if (!ip) {
        return new Response(JSON.stringify({ error: '缺少IP参数' }), { status: 400 });
    }
    const info = await getIPInfo(ip);
    return new Response(JSON.stringify(info || { error: '查询失败' }));
}

async function handleDeleteRecord(url) {
    const id = url.searchParams.get('id');
    const ip = url.searchParams.get('ip');
    const isTxt = url.searchParams.get('isTxt') === 'true';
    
    if (isTxt && ip) {
        // TXT记录删除单个IP
        const record = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${id}`);
        if (!record) {
            return new Response(JSON.stringify({ success: false, error: '获取记录失败' }), { status: 400 });
        }
        
        let txtContent = record.content.replace(/^"|"$/g, '');
        let ips = txtContent.split(',').map(i => i.trim()).filter(i => i);
        
        // 移除指定IP
        ips = ips.filter(i => i !== ip);
        
        if (ips.length === 0) {
            // 如果没有IP了，删除整个TXT记录
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${id}`, 'DELETE');
        } else {
            // 更新TXT记录
            const newContent = `"${ips.join(',')}"`;
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${id}`, 'PUT', {
                type: 'TXT',
                name: record.name,
                content: newContent,
                ttl: 60
            });
        }
        
        return new Response(JSON.stringify({ success: true }));
    }
    await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${id}`, 'DELETE');
    return new Response(JSON.stringify({ success: true }));
}

async function handleAddARecord(request) {
    const body = await request.json();
    const ip = body.ip;
    const targetIndex = body.targetIndex || 0;
    const target = CONFIG.targets[targetIndex];
    
    if (!ip || !target) {
        return new Response(JSON.stringify({ success: false, error: '参数错误' }), { status: 400 });
    }
    
    // 格式化IP:PORT
    const addr = ip.includes(':') ? ip : `${ip}:${target.port}`;
    
    const check = await checkProxyIP(addr);
    if (!check.success) {
        return new Response(JSON.stringify({ success: false, error: 'IP检测失败' }));
    }
    
    // TXT模式：追加到TXT记录
    if (target.mode === 'TXT') {
        const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=TXT`);
        
        let currentIPs = [];
        let recordId = null;
        
        if (records && records.length > 0) {
            recordId = records[0].id;
            let txtContent = records[0].content.replace(/^"|"$/g, '');
            currentIPs = txtContent.split(',').map(ip => ip.trim()).filter(ip => ip);
        }
        
        // 检查是否已存在
        if (currentIPs.includes(addr)) {
            return new Response(JSON.stringify({ success: false, error: 'IP已存在于TXT记录' }));
        }
        
        // 追加新IP
        currentIPs.push(addr);
        const newContent = `"${currentIPs.join(',')}"`;
        
        if (recordId) {
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${recordId}`, 'PUT', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
        } else {
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records`, 'POST', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
        }
        
        return new Response(JSON.stringify({ 
            success: true,
            colo: check.colo,
            time: check.responseTime,
            mode: 'TXT'
        }));
    }
    
    // A记录模式
    const result = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records`, 'POST', {
        type: 'A',
        name: target.domain,
        content: ip.split(':')[0], // A记录只需要IP部分
        ttl: 60,
        proxied: false
    });
    
    return new Response(JSON.stringify({ 
        success: !!result,
        colo: check.colo,
        time: check.responseTime,
        mode: 'A'
    }));
}

async function handleMaintain(url, env) {
    const isManual = url.searchParams.get('manual') === 'true';
    const res = await maintainAllDomains(env, isManual);
    
    // 将日志包含在响应中
    return new Response(JSON.stringify({
        ...res,
        // 确保所有日志都返回给前端
        allLogs: res.reports.flatMap(r => r.logs)
    }));
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
    
    return new Response(JSON.stringify({ mapping, pools }));
}

async function handleSaveDomainPoolMapping(request, env) {
    const body = await request.json();
    await env.IP_DATA.put('domain_pool_mapping', JSON.stringify(body.mapping));
    return new Response(JSON.stringify({ success: true }));
}

async function handleCreatePool(request, env) {
    const body = await request.json();
    const poolKey = body.poolKey;
    
    if (!poolKey || !poolKey.startsWith('pool_')) {
        return new Response(JSON.stringify({ success: false, error: '池名称必须以pool_开头' }), { status: 400 });
    }
    
    if (poolKey.length > 50 || !/^pool_[a-zA-Z0-9_]+$/.test(poolKey)) {
        return new Response(JSON.stringify({ success: false, error: '池名称只能包含字母数字下划线,最长50字符' }), { status: 400 });
    }
    
    if (poolKey === 'pool_domain_pool_mapping' || poolKey === 'pool_system') {
        return new Response(JSON.stringify({ success: false, error: '该池名称为系统保留' }), { status: 400 });
    }
    
    const existing = await env.IP_DATA.get(poolKey);
    if (existing !== null) {
        return new Response(JSON.stringify({ success: false, error: '池已存在' }), { status: 400 });
    }
    
    await env.IP_DATA.put(poolKey, '');
    return new Response(JSON.stringify({ success: true }));
}

async function handleDeletePool(url, env) {
    const poolKey = url.searchParams.get('poolKey');
    
    if (poolKey === 'pool') {
        return new Response(JSON.stringify({ success: false, error: '不能删除通用池' }), { status: 400 });
    }
    
    await env.IP_DATA.delete(poolKey);
    return new Response(JSON.stringify({ success: true }));
}

// ========== 核心函数  ==========

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
    let minActive = 3; // 默认值
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

function initConfig(env, request = null) {
    CONFIG.email = env.CF_MAIL || '';
    CONFIG.apiKey = env.CF_KEY || '';
    CONFIG.zoneId = env.CF_ZONEID || '';
    
    const domainsInput = env.CF_DOMAIN || '';
    if (domainsInput) {
        const parts = domainsInput.split(',').map(s => s.trim()).filter(s => s);
        CONFIG.targets = parts.map(parseTarget).filter(t => t !== null);
    }
    
    if (CONFIG.targets.length === 0) {
        CONFIG.targets = [{ mode: 'A', domain: '', port: '443', minActive: 3 }];
    }
    
    CONFIG.tgToken = env.TG_TOKEN || '';
    CONFIG.tgId = env.TG_ID || '';
    CONFIG.checkApi = env.CHECK_API || 'https://check.proxyip.cmliussss.net/check?proxyip=';
    CONFIG.dohApi = env.DOH_API || 'https://cloudflare-dns.com/dns-query';
    CONFIG.ipInfoEnabled = env.IP_INFO_ENABLED === 'true';
    CONFIG.ipInfoApi = env.IP_INFO_API || 'http://ip-api.com/json';
    
    if (request) {
        const url = new URL(request.url);
        CONFIG.projectUrl = `${url.protocol}//${url.host}`;
    }
}

// IP清洗逻辑
function parseIPLine(line) {
    line = line.trim();
    if (!line || line.startsWith('#')) return null;
    
    // IP:PORT 格式
    let match = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/);
    if (match) return `${match[1]}:${match[2]}`;
    
    // IP：PORT 格式（中文冒号）
    match = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})：(\d+)$/);
    if (match) return `${match[1]}:${match[2]}`;
    
    // IP 空格/Tab PORT
    const parts = line.split(/\s+/);
    if (parts.length === 2) {
        const ip = parts[0].trim();
        const port = parts[1].trim();
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && /^\d+$/.test(port)) {
            return `${ip}:${port}`;
        }
    }
    
    // 纯IP（默认443）
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(line)) {
        return `${line}:443`;
    }
    
    // 复杂格式
    const complexMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\D+(\d+)/);
    if (complexMatch) return `${complexMatch[1]}:${complexMatch[2]}`;
    
    return null;
}

function cleanIPList(text) {
    if (!text) return '';
    const set = new Set();
    text.split('\n').forEach(line => {
        const ip = parseIPLine(line);
        if (ip) set.add(ip);
    });
    return Array.from(set).join('\n');
}

async function cleanIPListAsync(text) {
    if (!text) return '';
    const set = new Set();
    const lines = text.split('\n');
    
    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;
        
        // 检测域名格式
        const domainMatch = line.match(/^([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}):?(\d+)?$/);
        if (domainMatch) {
            const domain = domainMatch[1];
            const port = domainMatch[2] || '443';
            
            if (domain.length > 253) continue;
            
            try {
                const ips = await resolveDomain(domain);
                if (ips && ips.length > 0) {
                    ips.slice(0, 50).forEach(ip => set.add(`${ip}:${port}`));
                }
                continue;
            } catch (e) {
                console.error(`Failed to resolve ${domain}:`, e);
                continue;
            }
        }
        
        // IP格式
        const ip = parseIPLine(line);
        if (ip) set.add(ip);
    }
    
    return Array.from(set).join('\n');
}

async function loadFromRemoteUrl(url) {
    try {
        const r = await fetch(url, { 
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.REMOTE_LOAD_TIMEOUT) 
        });
        if (r.ok) {
            const text = await r.text();
            return cleanIPList(text);
        }
    } catch (e) {
        console.error(`Failed to load from ${url}:`, e);
    }
    return '';
}

async function resolveDomain(domain) {
    try {
        const r = await fetch(`${CONFIG.dohApi}?name=${domain}&type=A`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(5000)
        });
        const d = await r.json();
        return d.Answer ? d.Answer.map(a => a.data) : [];
    } catch (e) {
        console.error('DNS A resolution failed:', e);
        return [];
    }
}

async function resolveTXTRecord(domain) {
    try {
        const r = await fetch(`${CONFIG.dohApi}?name=${domain}&type=TXT`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(5000)
        });
        const d = await r.json();
        
        if (!d.Answer || d.Answer.length === 0) {
            return { raw: '', ips: [] };
        }
        
        // 去掉DNS返回的引号
        let raw = d.Answer[0].data;
        raw = raw.replace(/^"|"$/g, ''); // 去掉首尾引号
        const ips = raw.split(',').map(ip => ip.trim()).filter(ip => ip);
        
        return { raw, ips };
    } catch (e) {
        console.error('DNS TXT resolution failed:', e);
        return { raw: '', ips: [] };
    }
}

async function getIPInfo(ip) {
    if (!CONFIG.ipInfoEnabled) return null;
    
    try {
        const cleanIP = ip.replace(/[\[\]]/g, '');
        const r = await fetch(
            `${CONFIG.ipInfoApi}/${cleanIP}?fields=status,country,countryCode,city,isp,as,asname&lang=zh-CN`,
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
        console.error(`IP信息查询失败 ${ip}:`, e);
    }
    
    return null;
}

async function getDomainStatus(target) {
    const result = {
        mode: target.mode,
        domain: target.domain,
        port: target.port,
        aRecords: [],
        txtRecords: [],
        error: null
    };
    
    if (target.mode === 'A' || target.mode === 'ALL') {
        const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=A`);
        if (records === null) {
            result.error = 'CF配置错误或API调用失败';
            return result;
        }
        if (records) {
            const checkPromises = records.map(r => checkProxyIP(`${r.content}:${target.port}`));
            const ipInfoPromises = CONFIG.ipInfoEnabled
                ? records.map(r => getIPInfo(r.content))
                : records.map(() => Promise.resolve(null));
            
            const [checkResults, ipInfoResults] = await Promise.all([
                Promise.all(checkPromises),
                Promise.all(ipInfoPromises)
            ]);
            
            result.aRecords = records.map((r, i) => ({
                id: r.id,
                ip: r.content,
                port: target.port,
                success: checkResults[i].success,
                colo: checkResults[i].colo || 'N/A',
                time: checkResults[i].responseTime || '-',
                ipInfo: ipInfoResults[i]
            }));
        }
    }
    
    if (target.mode === 'TXT' || target.mode === 'ALL') {
        const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=TXT`);
        if (records === null) {
            result.error = 'CF配置错误或API调用失败';
            return result;
        }
        if (records && records.length > 0) {
            let txtContent = records[0].content;
            txtContent = txtContent.replace(/^"|"$/g, '');
            const ips = txtContent.split(',').map(ip => ip.trim()).filter(ip => ip);
            
            const checkPromises = ips.map(addr => checkProxyIP(addr));
            const ipInfoPromises = CONFIG.ipInfoEnabled
                ? ips.map(addr => getIPInfo(addr.split(':')[0]))
                : ips.map(() => Promise.resolve(null));
            
            const [checkResults, ipInfoResults] = await Promise.all([
                Promise.all(checkPromises),
                Promise.all(ipInfoPromises)
            ]);
            
            const txtChecks = ips.map((addr, i) => ({
                ip: addr,
                success: checkResults[i].success,
                colo: checkResults[i].colo || 'N/A',
                time: checkResults[i].responseTime || '-',
                ipInfo: ipInfoResults[i]
            }));
            
            result.txtRecords = [{
                id: records[0].id,
                ips: txtChecks
            }];
        }
    }
    
    return result;
}

async function checkProxyIP(input) {
    let addr = input.trim();
    
    if (!addr.includes(':')) {
        addr = `${addr}:443`;
    }
    
    try {
        const r = await fetch(`${CONFIG.checkApi}${encodeURIComponent(addr)}`, {
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.CHECK_TIMEOUT)
        });
        return await r.json();
    } catch (e) {
        return { success: false };
    }
}

async function fetchCF(path, method = 'GET', body = null) {
    if (!CONFIG.email || !CONFIG.apiKey || !CONFIG.zoneId) {
        console.error('❌ Cloudflare配置不完整:', {
            email: !!CONFIG.email,
            apiKey: !!CONFIG.apiKey,
            zoneId: !!CONFIG.zoneId
        });
        return null;
    }
    
    const init = {
        method: method,
        headers: {
            'X-Auth-Email': CONFIG.email,
            'Authorization': `Bearer ${CONFIG.apiKey}`,
            'Content-Type': 'application/json'
        }
    };
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

// ========== 维护相关函数 ==========
async function getPoolConfig(env, domain) {
    const mappingJson = await env.IP_DATA.get('domain_pool_mapping') || '{}';
    const mapping = safeJSONParse(mappingJson, {});
    const poolKey = mapping[domain] || 'pool';
    return { poolKey, mapping };
}

async function updatePoolInKV(env, poolKey, poolList) {
    await env.IP_DATA.put(poolKey, poolList.join('\n'));
}

async function getCandidateIPs(env, target, addLog) {
    const { poolKey } = await getPoolConfig(env, target.domain);
    const pool = await env.IP_DATA.get(poolKey) || '';
    
    if (!pool) {
        addLog(`⚠️ ${poolKey} 为空`);
        return [];
    }
    
    let candidates = pool.split('\n').filter(l => l.trim());
    
    // TXT模式不过滤端口，A模式才过滤
    if (target.mode === 'A') {
        candidates = candidates.filter(l => {
            const [_, port] = l.split(':');
            return port === target.port;
        });
    }
    
    addLog(`📦 使用 ${poolKey}: ${candidates.length} 个候选IP`);
    return candidates;
}

async function maintainARecords(env, target, addLog, report) {
    addLog(`📋 维护A记录: ${target.domain}:${target.port} (最小活跃数: ${target.minActive})`);
    
    const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=A`);
    
    if (records === null) {
        addLog(`❌ 无法获取A记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }
    
    addLog(`当前A记录: ${records.length} 条`);
    
    const { poolKey } = await getPoolConfig(env, target.domain);
    let poolRaw = await env.IP_DATA.get(poolKey) || '';
    let poolList = poolRaw.split('\n').filter(l => l.trim());
    
    let activeIPs = [];
    
    // 检测现有记录
    for (const r of records) {
        const addr = `${r.content}:${target.port}`;
        const checkResult = await checkProxyIP(addr);
        
        report.checkDetails.push({
            ip: addr,
            status: checkResult.success ? '✅ 活跃' : '❌ 失效',
            colo: checkResult.colo || 'N/A',
            time: checkResult.responseTime || '-'
        });
        
        if (checkResult.success) {
            activeIPs.push(r.content);
            addLog(`  ✅ ${addr} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
        } else {
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${r.id}`, 'DELETE');
            report.removed.push({ ip: r.content, reason: '检测失效' });
            poolList = poolList.filter(p => p !== addr);
            report.poolRemoved++;
            addLog(`  ❌ ${addr} - 失效已删除`);
        }
    }
    
    report.beforeActive = activeIPs.length;
    
    // 补充IP
    if (activeIPs.length < target.minActive) {
        addLog(`需补充: ${target.minActive - activeIPs.length} 个`);
        
        const candidates = await getCandidateIPs(env, target, addLog);
        
        for (const item of candidates) {
            if (activeIPs.length >= target.minActive) break;
            
            const [ip, port] = item.split(':');
            if (activeIPs.includes(ip) || port !== target.port) continue;
            
            const checkResult = await checkProxyIP(item);
            
            if (checkResult.success) {
                await fetchCF(`/zones/${CONFIG.zoneId}/dns_records`, 'POST', {
                    type: 'A',
                    name: target.domain,
                    content: ip,
                    ttl: 60,
                    proxied: false
                });
                activeIPs.push(ip);
                
                report.added.push({
                    ip: ip,
                    colo: checkResult.colo || 'N/A',
                    time: checkResult.responseTime || '-'
                });
                
                addLog(`  ✅ ${item} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
            } else {
                poolList = poolList.filter(p => p !== item);
                report.poolRemoved++;
            }
        }
        
        await updatePoolInKV(env, poolKey, poolList);
        
        if (activeIPs.length < target.minActive) {
            report.poolExhausted = true;
            addLog(`⚠️ ${poolKey} 库存不足，无法达到最小活跃数 ${target.minActive}`);
        }
    } else {
        if (report.poolRemoved > 0) {
            await updatePoolInKV(env, poolKey, poolList);
        }
    }
    
    report.afterActive = activeIPs.length;
}

async function maintainTXTRecords(env, target, addLog, report) {
    addLog(`📝 维护TXT: ${target.domain} (最小活跃数: ${target.minActive})`);
    
    const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=TXT`);
    
    if (records === null) {
        addLog(`❌ 无法获取TXT记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }
    
    let currentIPs = [];
    let recordId = null;
    
    if (records && records.length > 0) {
        recordId = records[0].id;
        let txtContent = records[0].content;
        txtContent = txtContent.replace(/^"|"$/g, '');
        currentIPs = txtContent.split(',').map(ip => ip.trim()).filter(ip => ip);
        addLog(`当前TXT: ${currentIPs.length} 个IP`);
    }
    
    const { poolKey } = await getPoolConfig(env, target.domain);
    let poolRaw = await env.IP_DATA.get(poolKey) || '';
    let poolList = poolRaw.split('\n').filter(l => l.trim());
    
    let validIPs = [];
    
    // 检测现有IP
    for (const addr of currentIPs) {
        const checkResult = await checkProxyIP(addr);
        
        report.checkDetails.push({
            ip: addr,
            status: checkResult.success ? '✅ 活跃' : '❌ 失效',
            colo: checkResult.colo || 'N/A',
            time: checkResult.responseTime || '-'
        });
        
        if (checkResult.success) {
            validIPs.push(addr);
            addLog(`  ✅ ${addr} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
        } else {
            report.removed.push({ ip: addr, reason: '检测失效' });
            poolList = poolList.filter(p => p !== addr);
            report.poolRemoved++;
            addLog(`  ❌ ${addr} - 失效已删除`);
        }
    }
    
    report.beforeActive = validIPs.length;
    
    // 补充IP到最小活跃数
    if (validIPs.length < target.minActive) {
        addLog(`需补充: ${target.minActive - validIPs.length} 个`);
        
        const candidates = await getCandidateIPs(env, target, addLog);
        
        for (const item of candidates) {
            if (validIPs.length >= target.minActive) break;
            if (validIPs.includes(item)) continue;
            
            const checkResult = await checkProxyIP(item);
            
            if (checkResult.success) {
                validIPs.push(item);
                
                report.added.push({
                    ip: item,
                    colo: checkResult.colo || 'N/A',
                    time: checkResult.responseTime || '-'
                });
                
                addLog(`  ✅ ${item} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
            } else {
                poolList = poolList.filter(p => p !== item);
                report.poolRemoved++;
                addLog(`  ❌ ${item} - 检测失败，从池中移除`);
            }
        }
        
        await updatePoolInKV(env, poolKey, poolList);
        
        if (validIPs.length < target.minActive) {
            report.poolExhausted = true;
            addLog(`⚠️ ${poolKey} 库存不足，无法达到最小活跃数 ${target.minActive}`);
        }
    } else {
        if (report.poolRemoved > 0) {
            await updatePoolInKV(env, poolKey, poolList);
        }
    }
    
    // 更新TXT记录
    const newContent = validIPs.length > 0 ? `"${validIPs.join(',')}"` : '';
    const currentContent = currentIPs.length > 0 ? `"${currentIPs.join(',')}"` : '';
    
    if (newContent !== currentContent) {
        if (newContent === '' && recordId) {
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${recordId}`, 'DELETE');
            addLog(`📝 TXT记录已删除（所有IP失效）`);
        } else if (newContent !== '') {
            if (recordId) {
                await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${recordId}`, 'PUT', {
                    type: 'TXT',
                    name: target.domain,
                    content: newContent,
                    ttl: 60
                });
                addLog(`📝 TXT已更新`);
            } else {
                await fetchCF(`/zones/${CONFIG.zoneId}/dns_records`, 'POST', {
                    type: 'TXT',
                    name: target.domain,
                    content: newContent,
                    ttl: 60
                });
                addLog(`📝 TXT已创建`);
            }
        }
        report.txtUpdated = true;
    }
    
    report.afterActive = validIPs.length;
}

async function maintainAllDomains(env, isManual = false) {
    const allReports = [];
    const startTime = Date.now();
    
    const poolStats = new Map();
    
    const allKeys = await env.IP_DATA.list();
    for (const key of allKeys.keys) {
        if (key.name.startsWith('pool')) {
            const poolRaw = await env.IP_DATA.get(key.name) || '';
            const count = poolRaw ? poolRaw.split('\n').filter(l => l.trim()).length : 0;
            poolStats.set(key.name, { before: count, after: count });
        }
    }
    
    for (let i = 0; i < CONFIG.targets.length; i++) {
        const target = CONFIG.targets[i];
        
        const report = {
            target: target,
            domain: target.domain,
            mode: target.mode,
            port: target.port,
            minActive: target.minActive,
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
        
        if (target.mode === 'A') {
            await maintainARecords(env, target, addLog, report);
        } else if (target.mode === 'TXT') {
            await maintainTXTRecords(env, target, addLog, report);
        } else if (target.mode === 'ALL') {
            await maintainARecords(env, target, addLog, report);
            
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
            await maintainTXTRecords(env, txtTarget, addTxtLog, txtReport);
            
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
    
    for (const key of allKeys.keys) {
        if (key.name.startsWith('pool')) {
            const poolRaw = await env.IP_DATA.get(key.name) || '';
            const count = poolRaw ? poolRaw.split('\n').filter(l => l.trim()).length : 0;
            if (poolStats.has(key.name)) {
                poolStats.get(key.name).after = count;
            }
        }
    }
    
    const hasIPChanges = allReports.some(r => 
        r.added.length > 0 || 
        r.removed.length > 0 || 
        (r.txtAdded && r.txtAdded.length > 0) || 
        (r.txtRemoved && r.txtRemoved.length > 0)
    );
    
    const hasConfigError = allReports.some(r => r.configError);
    
    const exhaustedPools = [];
    for (const [poolKey, stats] of poolStats) {
        if (stats.after === 0 && stats.before > 0) {
            exhaustedPools.push(poolKey);
        }
    }
    const hasPoolExhausted = exhaustedPools.length > 0;
    
    const shouldNotify = isManual || hasIPChanges || hasPoolExhausted || hasConfigError;
    
    let tgResult = { sent: false, reason: 'no_need' };
    if (shouldNotify) {
        tgResult = await sendTG(allReports, poolStats, exhaustedPools, isManual);
    }
    
    console.log(`✅ 维护任务完成，总耗时: ${Date.now() - startTime}ms，处理域名: ${CONFIG.targets.length}个`);
    
    return {
        success: true,
        reports: allReports,
        poolStats: Object.fromEntries(poolStats),
        exhaustedPools,
        notified: tgResult.sent,
        tgStatus: tgResult,
        processingTime: Date.now() - startTime
    };
}

async function sendTG(reports, poolStats, exhaustedPools, isManual = false) {
    // 检查配置
    if (!CONFIG.tgToken || !CONFIG.tgId) {
        console.log('📱 TG未配置，跳过通知');
        return { sent: false, reason: 'not_configured', message: 'TG未配置' };
    }
    
    const modeLabel = { 'A': 'A记录', 'TXT': 'TXT记录', 'ALL': '双模式' };
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    
    let msg = isManual 
        ? `🔧 <b>DDNS 手动维护报告</b>\n`
        : `⚙️ <b>DDNS 自动维护报告</b>\n`;
    
    msg += `━━━━━━━━━━━━━━━━━━\n`;
    msg += `⏰ ${timestamp}\n\n`;
    
    // 检查配置错误
    const hasConfigError = reports.some(r => r.configError);
    if (hasConfigError) {
        msg += `⚠️ <b>警告: 检测到配置错误</b>\n`;
        msg += `请检查 CF_MAIL, CF_KEY, CF_ZONEID 是否正确配置\n\n`;
    }
    
    // 为TG通知批量查询IP归属地
    const allIPsForInfo = new Set();
    reports.forEach(report => {
        if (report.checkDetails) {
            report.checkDetails.forEach(detail => {
                const ipOnly = detail.ip.split(':')[0];
                allIPsForInfo.add(ipOnly);
            });
        }
        if (report.added) {
            report.added.forEach(item => {
                const ipOnly = item.ip.split(':')[0];
                allIPsForInfo.add(ipOnly);
            });
        }
        if (report.txtAdded) {
            report.txtAdded.forEach(item => {
                const ipOnly = item.ip.split(':')[0];
                allIPsForInfo.add(ipOnly);
            });
        }
    });
    
    // 批量查询归属地
    const ipInfoMap = new Map();
    if (CONFIG.ipInfoEnabled && allIPsForInfo.size > 0) {
        const ipInfoPromises = Array.from(allIPsForInfo).map(async ip => {
            const info = await getIPInfo(ip);
            if (info) ipInfoMap.set(ip, info);
        });
        await Promise.all(ipInfoPromises);
    }
    
    reports.forEach((report, index) => {
        if (index > 0) msg += `\n`;
        
        msg += `━━ <code>${report.domain}</code> ━━\n`;
        msg += `${modeLabel[report.mode]}`;
        if (report.mode === 'A' || report.mode === 'ALL') {
            msg += ` · 端口 ${report.port}`;
        }
        msg += ` · 最小活跃数 ${report.minActive}\n\n`;
        
        if (report.configError) {
            msg += `❌ <b>配置错误，无法获取记录</b>\n`;
        } else {
            if (report.checkDetails && report.checkDetails.length > 0) {
                report.checkDetails.forEach(detail => {
                    const statusIcon = detail.status.includes('✅') ? '✅' : '❌';
                    msg += `${statusIcon} <code>${detail.ip}</code>\n`;
                    
                    let info = `   ${detail.colo} · ${detail.time}ms`;
                    const ipOnly = detail.ip.split(':')[0];
                    const ipInfo = ipInfoMap.get(ipOnly);
                    if (ipInfo) {
                        info += ` · ${ipInfo.country}`;
                        if (ipInfo.asn) info += ` · ${ipInfo.asn}`;
                        if (ipInfo.isp) info += ` · ${ipInfo.isp}`;
                    }
                    msg += `${info}\n`;
                });
                msg += `\n`;
            }
            
            if (report.mode === 'A' || report.mode === 'ALL') {
                if (report.added.length > 0) {
                    msg += `📈 新增 ${report.added.length} 个IP\n`;
                    report.added.forEach(item => {
                        const displayIP = item.ip.includes(':') ? item.ip : `${item.ip}:${report.port}`;
                        msg += `   ✅ <code>${displayIP}</code>\n`;
                        let info = `      ${item.colo} · ${item.time}ms`;
                        const ipOnly = item.ip.split(':')[0];
                        const ipInfo = ipInfoMap.get(ipOnly);
                        if (ipInfo) {
                            info += ` · ${ipInfo.country}`;
                            if (ipInfo.asn) info += ` · ${ipInfo.asn}`;
                            if (ipInfo.isp) info += ` ${ipInfo.isp}`;
                        }
                        msg += `${info}\n`;
                    });
                }
                
                if (report.removed.length > 0) {
                    msg += `📉 移除 ${report.removed.length} 个IP\n`;
                    report.removed.forEach(item => {
                        msg += `   ❌ <code>${item.ip}</code>\n`;
                        msg += `      原因: ${item.reason}\n`;
                    });
                }
                
                if (report.added.length === 0 && report.removed.length === 0) {
                    msg += `✨ 所有IP正常，无变化\n`;
                }
                msg += `✅ 完成: ${report.afterActive}/${report.minActive}\n`;
            }
            
            if (report.mode === 'ALL' && report.txtActive !== undefined) {
                msg += `\n<b>📝 TXT记录</b>\n`;
                
                if (report.txtAdded && report.txtAdded.length > 0) {
                    msg += `📈 新增 ${report.txtAdded.length} 个IP\n`;
                    report.txtAdded.forEach(item => {
                        msg += `   ✅ <code>${item.ip}</code>\n`;
                        let info = `      ${item.colo} · ${item.time}ms`;
                        const ipOnly = item.ip.split(':')[0];
                        const ipInfo = ipInfoMap.get(ipOnly);
                        if (ipInfo) {
                            info += ` · ${ipInfo.country}`;
                            if (ipInfo.asn) info += ` · ${ipInfo.asn}`;
                            if (ipInfo.isp) info += ` ${ipInfo.isp}`;
                        }
                        msg += `${info}\n`;
                    });
                }
                
                if (report.txtRemoved && report.txtRemoved.length > 0) {
                    msg += `📉 移除 ${report.txtRemoved.length} 个IP\n`;
                    report.txtRemoved.forEach(item => {
                        msg += `   ❌ <code>${item.ip}</code>\n`;
                        msg += `      原因: ${item.reason}\n`;
                    });
                }
                
                if ((!report.txtAdded || report.txtAdded.length === 0) && 
                    (!report.txtRemoved || report.txtRemoved.length === 0)) {
                    msg += `✨ 所有IP正常，无变化\n`;
                }
                msg += `✅ 完成: ${report.txtActive}/${report.minActive}\n`;
            }
            
            if (report.mode === 'TXT') {
                if (report.added.length > 0) {
                    msg += `📈 新增 ${report.added.length} 个IP\n`;
                    report.added.forEach(item => {
                        msg += `   ✅ <code>${item.ip}</code>\n`;
                        let info = `      ${item.colo} · ${item.time}ms`;
                        const ipOnly = item.ip.split(':')[0];
                        const ipInfo = ipInfoMap.get(ipOnly);
                        if (ipInfo) {
                            info += ` · ${ipInfo.country}`;
                            if (ipInfo.asn) info += ` · ${ipInfo.asn}`;
                            if (ipInfo.isp) info += ` ${ipInfo.isp}`;
                        }
                        msg += `${info}\n`;
                    });
                }
                
                if (report.removed.length > 0) {
                    msg += `📉 移除 ${report.removed.length} 个IP\n`;
                    report.removed.forEach(item => {
                        msg += `   ❌ <code>${item.ip}</code>\n`;
                        msg += `      原因: ${item.reason}\n`;
                    });
                }
                
                if (report.added.length === 0 && report.removed.length === 0) {
                    msg += `✨ 所有IP正常，无变化\n`;
                }
                msg += `✅ 完成: ${report.afterActive}/${report.minActive}\n`;
            }
        }
    });
    
    msg += `\n━━━━━━━━━━━━━━━━━━\n`;
    msg += `📦 <b>IP池库存统计</b>\n`;
    
    for (const [poolKey, stats] of poolStats) {
        const displayName = poolKey === 'pool' ? '通用池' : poolKey.replace('pool_', '') + '池';
        msg += `\n<b>${displayName}</b>\n`;
        msg += `   维护前: ${stats.before} 个\n`;
        msg += `   维护后: ${stats.after} 个\n`;
        
        const change = stats.after - stats.before;
        if (change !== 0) {
            const changeSymbol = change > 0 ? '📈' : '📉';
            msg += `   ${changeSymbol} 变化: ${change > 0 ? '+' : ''}${change}\n`;
        }
        
        if (stats.after === 0 && stats.before > 0) {
            msg += `   ⚠️ <b>警告：${displayName}已枯竭！</b>\n`;
        } else if (stats.after < 10) {
            msg += `   ⚠️ 库存较低\n`;
        }
    }
    
    if (isManual && CONFIG.projectUrl) {
        msg += `\n🔗 <a href="${CONFIG.projectUrl}">打开管理面板</a>\n`;
    }
    
    try {
        const response = await fetch(`https://api.telegram.org/bot${CONFIG.tgToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: CONFIG.tgId,
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

// ========== 前端HTML渲染函数 ==========
function renderHTML(C) {
    const targetsJson = JSON.stringify(C.targets);
    const settingsJson = JSON.stringify(GLOBAL_SETTINGS);
    const ipInfoEnabled = C.ipInfoEnabled;
    
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro v5.3 - IP管理面板</title>
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
            height: 350px;
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
            padding: 12px;
            background: #f5f5f7;
            border-radius: 12px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .result-item code {
            background: #fff;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 13px;
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
        }
    </style>
</head>
<body class="pb-5">

<a href="https://github.com/231128ikun/DDNS-cf-proxyip" class="github-corner" aria-label="View source on GitHub" target="_blank">
    <svg viewBox="0 0 250 250" aria-hidden="true">
        <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
        <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
        <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
</a>

<div class="container hero">
    <h1>
        🌐 DDNS Pro 多域名管理
        <span class="version-badge">v5.3</span>
    </h1>
    <div class="domain-selector">
        <select id="domain-select" class="form-select" onchange="switchDomain()">
            ${C.targets.map((t, i) => {
                const modeLabel = {'A': 'A记录', 'TXT': 'TXT', 'ALL': '双模式'};
                const label = `${t.domain} · ${modeLabel[t.mode]}${t.mode !== 'TXT' ? ' · ' + t.port : ''} · 最小${t.minActive}`;
                return `<option value="${i}">${label}</option>`;
            }).join('')}
        </select>
    </div>
</div>

<div class="container">
    <!-- 解析实况 -->
    <div class="card p-3">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h6 class="m-0 fw-bold">📡 解析实况</h6>
            <button class="btn btn-primary btn-sm" onclick="refreshStatus()">🔄 刷新</button>
        </div>
        
        <div id="manual-add-section" class="mb-3">
            <div class="input-group">
                <input type="text" id="manual-add-ip" class="form-control" placeholder="手动添加IP (如: 1.2.3.4 或 1.2.3.4:443)">
                <button class="btn btn-success" onclick="manualAddIP()">➕ 添加</button>
            </div>
        </div>
        
        <div class="table-responsive">
            <table class="table text-center">
                <thead>
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

    <div class="row">
        <!-- IP管理 -->
        <div class="col-lg-7">
            <div class="card p-4 mb-3">
                <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                    <div>
                        <h6 class="m-0 fw-bold d-inline">📦 IP库管理</h6>
                        <div class="config-info ms-2">
                            ⚙️ 并发: ${GLOBAL_SETTINGS.CONCURRENT_CHECKS} | 超时: ${GLOBAL_SETTINGS.CHECK_TIMEOUT}ms
                        </div>
                    </div>
                    <div class="btn-group btn-group-sm">
                        <select id="pool-selector" class="form-select form-select-sm" style="width:150px" onchange="switchPool()">
                            <option value="pool">通用池</option>
                        </select>
                        <button class="btn btn-outline-primary" onclick="createNewPool()" title="新建池">➕</button>
                        <button class="btn btn-outline-danger" onclick="deleteCurrentPool()" title="删除池">🗑️</button>
                    </div>
                </div>
                
                <!-- IP输入方式选择 -->
                <div class="mb-3">
                    <div class="btn-group w-100" role="group">
                        <input type="radio" class="btn-check" name="inputMode" id="mode-manual" checked autocomplete="off">
                        <label class="btn btn-outline-primary" for="mode-manual" onclick="switchInputMode('manual')">📝 手动输入</label>
                        
                        <input type="radio" class="btn-check" name="inputMode" id="mode-remote" autocomplete="off">
                        <label class="btn btn-outline-primary" for="mode-remote" onclick="switchInputMode('remote')">🌐 远程TXT</label>
                        
                        <input type="radio" class="btn-check" name="inputMode" id="mode-load" autocomplete="off">
                        <label class="btn btn-outline-primary" for="mode-load" onclick="loadCurrentPool()">📂 加载当前池</label>
                    </div>
                </div>
                
                <!-- 手动输入区 -->
                <div id="input-manual" class="input-section">
                    <textarea id="ip-input" class="form-control mb-2" rows="8" placeholder="每行一个，支持以下格式：
1.2.3.4:443
1.2.3.4 443
1.2.3.4
example.com:443 (自动解析域名)"></textarea>
                    <div class="format-hint">
                        💡 <strong>支持从Excel/CSV直接复制粘贴</strong><br>
                        支持 IP:PORT | IP 空格 PORT | 域名:PORT | 纯IP (默认443端口)
                    </div>
                </div>
                
                <!-- 远程加载区 -->
                <div id="input-remote" class="input-section" style="display:none">
                    <div class="input-group mb-2">
                        <input type="text" id="remote-url" class="form-control" placeholder="远程TXT文件URL">
                        <button class="btn btn-primary" onclick="loadRemoteUrl()">🔄 加载</button>
                    </div>
                    <textarea id="ip-input-remote" class="form-control" rows="8" placeholder="加载的IP将显示在这里..." readonly></textarea>
                </div>
                
                <div class="row g-2 mt-2">
                    <div class="col-4">
                        <button id="btn-check" class="btn btn-warning btn-sm w-100 text-white" onclick="batchCheck()">⚡ 检测清洗</button>
                    </div>
                    <div class="col-4">
                        <button class="btn btn-success btn-sm w-100" onclick="saveToCurrentPool()">💾 保存到当前池</button>
                    </div>
                    <div class="col-4">
                        <button class="btn btn-outline-info btn-sm w-100" onclick="showPoolInfo()">📊 当前池: <span id="pool-count">0</span></button>
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
            
            <!-- Check ProxyIP -->
            <div class="card p-4">
                <h6 class="mb-3 fw-bold">🔍 Check ProxyIP</h6>
                <div class="input-group mb-3">
                    <input type="text" id="lookup-domain" class="form-control" placeholder="域名, IP:端口, 或 txt@域名">
                    <button class="btn btn-info text-white" onclick="lookupDomain()">🔎 探测</button>
                </div>
                <div id="lookup-results"></div>
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
                <button class="btn btn-dark w-100" onclick="runMaintain()">🔧 执行全部维护</button>
            </div>
        </div>
    </div>
</div>

<script>
    const TARGETS = ${targetsJson};
    const SETTINGS = ${settingsJson};
    const IP_INFO_ENABLED = ${ipInfoEnabled};
    let currentTargetIndex = 0;
    let currentInputMode = 'manual';
    let currentPool = 'pool';
    let abortController = null;
    let domainPoolMapping = {};
    let availablePools = ['pool'];
    
    const log = (m, t='info', skipTimestamp=false) => {
        const w = document.getElementById('log-window');
        const colors = { success: '#32d74b', error: '#ff453a', info: '#64d2ff', warn: '#ffd60a' };
        
        let output;
        if (skipTimestamp) {
            output = \`<div style="color:\${colors[t]}">\${m}</div>\`;
        } else {
            const time = new Date().toLocaleTimeString('zh-CN');
            output = \`<div style="color:\${colors[t]}">[<span style="color:#8e8e93">\${time}</span>] \${m}</div>\`;
        }
        
        w.innerHTML += output;
        w.scrollTop = w.scrollHeight;
    };
    
    function normalizeIPFormat(input) {
        if (!input) return null;
        
        input = input.trim();
        
        if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d+$/.test(input)) {
            return input;
        }
        
        const parts = input.split(/\\s+/);
        if (parts.length === 2) {
            const ip = parts[0].trim();
            const port = parts[1].trim();
            
            if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(ip) && /^\\d+$/.test(port)) {
                return \`\${ip}:\${port}\`;
            }
        }
        
        if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(input)) {
            return \`\${input}:443\`;
        }
        
        const match = input.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})：(\\d+)$/);
        if (match) {
            return \`\${match[1]}:\${match[2]}\`;
        }
        
        return null;
    }
    
    function formatIPInfo(ipInfo) {
        if (!ipInfo) return '';
        
        let html = '';
        if (ipInfo.country) {
            html += \`<span class="ip-info-tag">\${ipInfo.country}</span>\`;
        }
        if (ipInfo.asn) {
            html += \`<span class="ip-info-tag">\${ipInfo.asn}</span>\`;
        }
        return html;
    }
    
    function switchDomain() {
        currentTargetIndex = parseInt(document.getElementById('domain-select').value);
        const target = TARGETS[currentTargetIndex];
        log(\`切换到: \${target.domain} (\${target.mode})\`);
        
        // 所有模式都显示手动添加（TXT模式现在也支持追加）
        const manualSection = document.getElementById('manual-add-section');
        manualSection.style.display = 'block';
        
        refreshStatus();
    }
    
    function switchInputMode(mode) {
        currentInputMode = mode;
        document.getElementById('input-manual').style.display = mode === 'manual' ? 'block' : 'none';
        document.getElementById('input-remote').style.display = mode === 'remote' ? 'block' : 'none';
        
        if (mode === 'load') {
            loadCurrentPool();
            setTimeout(() => {
                document.getElementById('mode-manual').checked = true;
                currentInputMode = 'manual';
            }, 100);
        }
    }
    
    function getCurrentInput() {
        if (currentInputMode === 'remote') {
            return document.getElementById('ip-input-remote');
        }
        return document.getElementById('ip-input');
    }
    
    async function loadRemoteUrl() {
        const url = document.getElementById('remote-url').value.trim();
        if (!url) {
            log('❌ 请输入URL', 'error');
            return;
        }
        
        log(\`🌐 加载: \${url}\`, 'warn');
        try {
            const r = await fetch('/api/load-remote-url', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ url })
            }).then(r => r.json());
            
            if (r.success) {
                document.getElementById('ip-input-remote').value = r.ips || '';
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
            const r = await fetch(\`/api/get-pool?poolKey=\${currentPool}\`).then(r => r.json());
            document.getElementById('ip-input').value = r.pool || '';
            document.getElementById('pool-count').innerText = r.count;
            log(\`✅ 已加载 \${r.count} 个IP\`, 'success');
        } catch (e) {
            log('❌ 加载失败', 'error');
        }
    }
    
    async function saveToCurrentPool() {
        const content = getCurrentInput().value;
        if (!content.trim()) {
            log('❌ 内容为空', 'error');
            return;
        }
        
        log(\`💾 保存到 \${currentPool}...\`, 'warn');
        try {
            const r = await fetch('/api/save-pool', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ 
                    pool: content,
                    poolKey: currentPool
                })
            }).then(r => r.json());
            
            if (r.success) {
                const displayName = currentPool === 'pool' ? '通用池' : currentPool.replace('pool_', '') + '池';
                log(\`✅ 已添加 \${r.added} 个IP到 \${displayName}\`, 'success');
                document.getElementById('pool-count').innerText = r.count;
                getCurrentInput().value = '';
            } else {
                log(\`❌ 失败: \${r.error}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 保存失败\`, 'error');
        }
    }
    
    async function showPoolInfo() {
        try {
            const r = await fetch(\`/api/get-pool?poolKey=\${currentPool}\`).then(r => r.json());
            document.getElementById('pool-count').innerText = r.count;
        } catch (e) {
            log('❌ 查询失败', 'error');
        }
    }
    
    async function batchCheck() {
        const btn = document.getElementById('btn-check');
        const input = getCurrentInput();
        const lines = input.value.split('\\n').filter(i => i.trim());
        
        if (!lines.length) {
            log('❌ 请先输入IP', 'error');
            return;
        }
        
        if (abortController) {
            abortController.abort();
            abortController = null;
            btn.textContent = '⚡ 检测清洗';
            btn.classList.remove('btn-danger');
            btn.classList.add('btn-warning');
            log('🛑 已停止检测', 'warn');
            document.getElementById('pg-bar').style.width = '0%';
            return;
        }
        
        abortController = new AbortController();
        const signal = abortController.signal;
        
        btn.textContent = '🛑 停止检测';
        btn.classList.remove('btn-warning');
        btn.classList.add('btn-danger');
        
        let valid = [], total = lines.length, checked = 0;
        const pg = document.getElementById('pg-bar');
        
        log(\`🚀 开始检测 \${total} 个IP (并发: \${SETTINGS.CONCURRENT_CHECKS})\`, 'warn');
        
        const chunkSize = SETTINGS.CONCURRENT_CHECKS;
        
        try {
            for (let i = 0; i < lines.length; i += chunkSize) {
                if (signal.aborted) break;
                
                const chunk = lines.slice(i, i + chunkSize);
                
                await Promise.all(chunk.map(async (line) => {
                    if (signal.aborted) return;
                    
                    const item = line.trim();
                    if (!item) return;
                    
                    const normalized = normalizeIPFormat(item);
                    if (!normalized) {
                        log(\`  ⚠️  格式错误: \${item}\`, 'warn');
                        checked++;
                        pg.style.width = (checked / total * 100) + '%';
                        return;
                    }
                    
                    try {
                        const r = await fetch(\`/api/check-ip?ip=\${encodeURIComponent(normalized)}\`, {
                            signal: signal
                        }).then(r => r.json());
                        
                        checked++;
                        
                        if (r.success) {
                            valid.push(normalized);
                            log(\`  ✅ \${normalized} - \${r.colo} (\${r.responseTime}ms)\`, 'success');
                        } else {
                            log(\`  ❌ \${normalized}\`, 'error');
                        }
                    } catch (e) {
                        if (e.name !== 'AbortError') {
                            checked++;
                            log(\`  ❌ \${normalized}\`, 'error');
                        }
                    }
                    
                    if (!signal.aborted) {
                        pg.style.width = (checked / total * 100) + '%';
                    }
                }));
            }
            
            if (!signal.aborted) {
                input.value = valid.join('\\n');
                log(\`✅ 检测完成: \${valid.length}/\${total} 有效\`, 'success');
            }
        } catch (e) {
            if (e.name !== 'AbortError') {
                log(\`❌ 出错: \${e.message}\`, 'error');
            }
        } finally {
            abortController = null;
            btn.textContent = '⚡ 检测清洗';
            btn.classList.remove('btn-danger');
            btn.classList.add('btn-warning');
            setTimeout(() => { pg.style.width = '0%'; }, 1000);
        }
    }
    
    async function refreshStatus() {
        const t = document.getElementById('status-table');
        const txtDiv = document.getElementById('txt-status');
        const colspan = IP_INFO_ENABLED ? '6' : '5';
        t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">🔄 查询中...</td></tr>\`;
        txtDiv.innerHTML = '';
        
        try {
            const data = await fetch(\`/api/current-status?target=\${currentTargetIndex}\`).then(r => r.json());
            
            if (data.error) {
                t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ \${data.error}<br><small>请检查 CF_MAIL, CF_KEY, CF_ZONEID 配置</small></td></tr>\`;
                return;
            }
            
            if ((data.mode === 'TXT' || data.mode === 'ALL') && data.txtRecords && data.txtRecords.length > 0) {
                const record = data.txtRecords[0];
                let html = '<h6 class="fw-bold mb-2 mt-3">📝 TXT记录内容</h6><div class="p-3 bg-light rounded-3">';
                record.ips.forEach(ip => {
                    html += \`<div class="txt-record-item">
                        <div class="txt-ip-line">
                            <code class="txt-ip-code">\${ip.ip}</code>
                            <div class="txt-info-group">
                                <span class="badge \${ip.success?'bg-success':'bg-danger'}">\${ip.success?'✅':'❌'} \${ip.colo} · \${ip.time}ms</span>
                                \${IP_INFO_ENABLED && ip.ipInfo ? formatIPInfo(ip.ipInfo) : ''}
                                <a href="javascript:deleteTxtIP('\${record.id}', '\${ip.ip}')" class="text-danger text-decoration-none small fw-bold">🗑️</a>
                            </div>
                        </div>
                    </div>\`;
                });
                html += '</div>';
                txtDiv.innerHTML = html;
            }
            
            if (data.mode === 'A' || data.mode === 'ALL') {
                if (!data.aRecords || data.aRecords.length === 0) {
                    t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">暂无A记录</td></tr>\`;
                } else {
                    t.innerHTML = data.aRecords.map(r => \`
                        <tr>
                            <td class="fw-bold">\${r.ip}</td>
                            <td><span class="badge bg-light text-dark">\${r.colo}</span></td>
                            <td>\${r.time}ms</td>
                            <td><span class="badge \${r.success?'bg-success':'bg-danger'}">\${r.success?'✅':'❌'}</span></td>
                            \${IP_INFO_ENABLED ? \`<td>\${r.ipInfo ? formatIPInfo(r.ipInfo) : '-'}</td>\` : ''}
                            <td><a href="javascript:deleteRecord('\${r.id}')" class="text-danger text-decoration-none small fw-bold">🗑️</a></td>
                        </tr>
                    \`).join('');
                }
            } else if (data.mode === 'TXT') {
                t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-secondary p-4">TXT模式，查看下方TXT记录</td></tr>\`;
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
            const r = await fetch('/api/add-a-record', {
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
        
        log(\`🔍 查询: \${val}\`, 'info');
        
        try {
            if (val.startsWith('txt@')) {
                const data = await fetch(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`).then(r => r.json());
                log(\`📝 TXT: \${data.ips.length} 个IP\`, 'success');
                const res = document.getElementById('lookup-results');
                res.innerHTML = '<div class="alert alert-info mb-2 py-2"><small>📝 TXT记录内容</small></div>';
                
                const checkPromises = data.ips.map(ip => checkAndDisplayIP(ip, res));
                const results = await Promise.all(checkPromises);
                
                const activeCount = results.filter(r => r === true).length;
                const totalCount = data.ips.length;
                log(\`📊 检测完成: \${activeCount}/\${totalCount} 活跃\`, activeCount === totalCount ? 'success' : (activeCount > 0 ? 'warn' : 'error'));
                return;
            }
            
            const isIP = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?$/.test(val);
            
            if (isIP) {
                log(\`🔌 直接检测: \${val}\`, 'info');
                const res = document.getElementById('lookup-results');
                res.innerHTML = '';
                const result = await checkAndDisplayIP(val, res);
                log(\`📊 检测完成: \${result ? '1/1' : '0/1'} 活跃\`, result ? 'success' : 'error');
            } else {
                const data = await fetch(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`).then(r => r.json());
                
                if (!data.ips || data.ips.length === 0) {
                    log(\`⚠️  域名无A记录\`, 'warn');
                    return;
                }
                
                log(\`📡 \${data.ips.length} 个IP (端口: \${data.port})\`, 'success');
                
                const res = document.getElementById('lookup-results');
                res.innerHTML = '';
                
                const targets = data.ips.map(ip => \`\${ip}:\${data.port}\`);
                const checkPromises = targets.map(target => checkAndDisplayIP(target, res));
                const results = await Promise.all(checkPromises);
                
                const activeCount = results.filter(r => r === true).length;
                const totalCount = targets.length;
                log(\`📊 检测完成: \${activeCount}/\${totalCount} 活跃\`, activeCount === totalCount ? 'success' : (activeCount > 0 ? 'warn' : 'error'));
            }
        } catch (e) {
            log(\`❌ 失败: \${e.message}\`, 'error');
        }
    }
    
    async function checkAndDisplayIP(ip, container) {
        const id = 'check-' + Math.random().toString(36).substr(2, 9);
        const div = document.createElement('div');
        div.className = 'result-item';
        div.innerHTML = \`
            <code>\${ip}</code>
            <span class="info" id="\${id}">检测中...</span>
            <button class="btn btn-sm btn-outline-primary" onclick="addToInput('\${ip}')" style="display:none" id="btn-\${id}">➕</button>
        \`;
        container.appendChild(div);
        
        try {
            const result = await fetch(\`/api/check-ip?ip=\${encodeURIComponent(ip)}\`).then(r => r.json());
            const info = document.getElementById(id);
            const btn = document.getElementById('btn-' + id);
            
            if (result.success) {
                let infoHTML = \`<span class="text-success">✅ \${result.colo} · \${result.responseTime}ms</span>\`;
                
                if (IP_INFO_ENABLED) {
                    const ipOnly = ip.split(':')[0];
                    const ipInfo = await fetch(\`/api/ip-info?ip=\${encodeURIComponent(ipOnly)}\`).then(r => r.json());
                    if (ipInfo && !ipInfo.error) {
                        infoHTML += formatIPInfo(ipInfo);
                    }
                }
                
                info.innerHTML = infoHTML;
                btn.style.display = 'block';
                log(\`  ✅ \${ip} - \${result.colo} (\${result.responseTime}ms)\`, 'success');
                return true;
            } else {
                info.innerHTML = '<span class="text-danger">❌ 失效</span>';
                log(\`  ❌ \${ip}\`, 'error');
                return false;
            }
        } catch (e) {
            const info = document.getElementById(id);
            if (info) {
                info.innerHTML = '<span class="text-danger">❌ 出错</span>';
            }
            return false;
        }
    }
    
    function addToInput(ip) {
        const input = getCurrentInput();
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
            await fetch(\`/api/delete-record?id=\${id}\`);
            log('🗑️  已删除', 'success');
            refreshStatus();
        } catch (e) {
            log(\`❌ 失败\`, 'error');
        }
    }

    async function deleteTxtIP(recordId, ip) {
        if (!confirm(\`确认删除 \${ip}？\`)) return;
        
        try {
            await fetch(\`/api/delete-record?id=\${recordId}&ip=\${encodeURIComponent(ip)}&isTxt=true\`);
            log('🗑️ 已从TXT记录删除', 'success');
            refreshStatus();
        } catch (e) {
            log(\`❌ 删除失败\`, 'error');
        }
    }
    
    async function runMaintain() {
        log('🔧 启动维护...', 'warn');
        
        try {
            const r = await fetch('/api/maintain?manual=true').then(r => r.json());
            
            // 显示所有详细日志
            if (r.allLogs && r.allLogs.length > 0) {
                r.allLogs.forEach(msg => log(msg, 'info', true));
            }
            
            log(\`✅ 维护完成，耗时: \${r.processingTime}ms\`, 'success');
            
            // 根据 tgStatus 显示不同的通知状态
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
            const r = await fetch('/api/get-domain-pool-mapping').then(r => r.json());
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
        selector.innerHTML = availablePools.map(pool => {
            const displayName = pool === 'pool' ? '通用池' : pool.replace('pool_', '') + '池';
            return \`<option value="\${pool}">\${displayName}</option>\`;
        }).join('');
        selector.value = currentPool;
    }
    
    function updateDomainBindingTable() {
        const tbody = document.getElementById('domain-binding-list');
        const domains = TARGETS.map(t => t.domain);
        
        tbody.innerHTML = domains.map(domain => {
            const boundPool = domainPoolMapping[domain] || 'pool';
            const options = availablePools.map(pool => {
                const displayName = pool === 'pool' ? '通用池' : pool.replace('pool_', '') + '池';
                const selected = pool === boundPool ? 'selected' : '';
                return \`<option value="\${pool}" \${selected}>\${displayName}</option>\`;
            }).join('');
            
            return \`
                <tr>
                    <td><code>\${domain}</code></td>
                    <td>
                        <select class="form-select form-select-sm" 
                                onchange="bindDomainToPool('\${domain}', this.value)">
                            \${options}
                        </select>
                    </td>
                </tr>
            \`;
        }).join('');
    }
    
    async function createNewPool() {
        const name = prompt('输入池名称 (字母数字下划线,如: tw, us, hk)');
        if (!name) return;
        
        if (!/^[a-zA-Z0-9_]+$/.test(name)) {
            alert('池名称只能包含字母、数字和下划线!');
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
            const r = await fetch('/api/create-pool', {
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
        if (currentPool === 'pool') {
            alert('不能删除通用池!');
            return;
        }
        
        if (!confirm(\`确认删除 \${currentPool}?\`)) return;
        
        try {
            await fetch(\`/api/delete-pool?poolKey=\${currentPool}\`);
            
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
        const displayName = currentPool === 'pool' ? '通用池' : currentPool.replace('pool_', '') + '池';
        log(\`📦 切换到: \${displayName}\`, 'info');
        showPoolInfo();
    }
    
    async function bindDomainToPool(domain, poolKey) {
        domainPoolMapping[domain] = poolKey;
        
        try {
            await fetch('/api/save-domain-pool-mapping', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ mapping: domainPoolMapping })
            });
            
            const displayName = poolKey === 'pool' ? '通用池' : poolKey.replace('pool_', '') + '池';
            log(\`✅ \${domain} → \${displayName}\`, 'success');
        } catch (e) {
            log('❌ 绑定失败', 'error');
        }
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