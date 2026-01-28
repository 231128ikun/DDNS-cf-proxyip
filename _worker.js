/**
 * DDNS Pro & Proxy IP Manager v4.2
 * 新增：IP归属地查询功能（可选）
 */

// ========== 运行时配置 ==========
let CONFIG = {
    email: '',
    apiKey: '',
    zoneId: '',
    targets: [],
    sourceDomain: '',
    sourceDomainPort: '443',
    minActive: 3,
    tgToken: '',
    tgId: '',
    checkApi: '',
    dohApi: '',
    projectUrl: '',
    // 新增：IP信息查询配置
    ipInfoEnabled: false,
    ipInfoApi: ''
};

// ========== 全局设置 ==========
const GLOBAL_SETTINGS = {
    CONCURRENT_CHECKS: 10,      // 并发检测数量
    CHECK_TIMEOUT: 6000,        // 检测单个 IP 的超时（毫秒）
    REMOTE_LOAD_TIMEOUT: 10000, // 加载远程 URL 的超时（毫秒）
    IP_INFO_TIMEOUT: 3000       // IP信息查询超时（毫秒）
};

export default {
    async fetch(request, env, ctx) {
        initConfig(env, request);
        const url = new URL(request.url);

        if (url.pathname === '/') {
            return new Response(renderHTML(CONFIG), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }

        // Favicon
        if (url.pathname === '/favicon.ico') {
            return new Response(null, { status: 204 });
        }

        try {
            // 获取IP池
            if (url.pathname === '/api/get-pool') {
                const pool = await env.IP_DATA.get('pool') || '';
                const count = pool.trim() ? pool.trim().split('\n').length : 0;
                if (url.searchParams.get('onlyCount') === 'true') {
                    return new Response(JSON.stringify({ count }));
                }
                return new Response(JSON.stringify({ pool, count }));
            }

            // 保存IP池（追加模式）
            if (url.pathname === '/api/save-pool') {
                const body = await request.json();
                const newIPs = cleanIPList(body.pool || '');
                
                if (!newIPs) {
                    return new Response(JSON.stringify({ success: false, error: '没有有效IP' }), { status: 400 });
                }
                
                const existingPool = await env.IP_DATA.get('pool') || '';
                const existingSet = new Set(existingPool.split('\n').filter(l => l.trim()));
                
                newIPs.split('\n').forEach(ip => {
                    if (ip.trim()) existingSet.add(ip.trim());
                });
                
                const finalPool = Array.from(existingSet).join('\n');
                await env.IP_DATA.put('pool', finalPool);
                
                return new Response(JSON.stringify({
                    success: true,
                    count: existingSet.size,
                    added: existingSet.size - (existingPool ? existingPool.split('\n').filter(l => l.trim()).length : 0)
                }));
            }

            // 从远程URL加载IP
            if (url.pathname === '/api/load-remote-url') {
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

            // 获取当前解析状态
            if (url.pathname === '/api/current-status') {
                const targetIndex = parseInt(url.searchParams.get('target') || '0');
                const target = CONFIG.targets[targetIndex];
                if (!target) {
                    return new Response(JSON.stringify({ error: '无效的目标' }), { status: 400 });
                }
                const status = await getDomainStatus(target);
                return new Response(JSON.stringify(status));
            }

            // 查询域名解析
            if (url.pathname === '/api/lookup-domain') {
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

            // 检测单个IP
            if (url.pathname === '/api/check-ip') {
                const target = url.searchParams.get('ip');
                const res = await checkProxyIP(target);
                return new Response(JSON.stringify(res));
            }

            // 新增：查询IP归属地信息
            if (url.pathname === '/api/ip-info') {
                const ip = url.searchParams.get('ip');
                if (!ip) {
                    return new Response(JSON.stringify({ error: '缺少IP参数' }), { status: 400 });
                }
                const info = await getIPInfo(ip);
                return new Response(JSON.stringify(info || { error: '查询失败' }));
            }

            // 删除DNS记录
            if (url.pathname === '/api/delete-record') {
                const id = url.searchParams.get('id');
                await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${id}`, 'DELETE');
                return new Response(JSON.stringify({ success: true }));
            }

            // 添加A记录
            if (url.pathname === '/api/add-a-record') {
                const body = await request.json();
                const ip = body.ip;
                const targetIndex = body.targetIndex || 0;
                const target = CONFIG.targets[targetIndex];
                
                if (!ip || !target) {
                    return new Response(JSON.stringify({ success: false, error: '参数错误' }), { status: 400 });
                }
                
                const check = await checkProxyIP(`${ip}:${target.port}`);
                if (!check.success) {
                    return new Response(JSON.stringify({ success: false, error: 'IP检测失败' }));
                }
                
                const result = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records`, 'POST', {
                    type: 'A',
                    name: target.domain,
                    content: ip,
                    ttl: 60,
                    proxied: false
                });
                
                return new Response(JSON.stringify({ 
                    success: !!result,
                    colo: check.colo,
                    time: check.responseTime
                }));
            }

            // 执行维护任务
            if (url.pathname === '/api/maintain') {
                const isManual = url.searchParams.get('manual') === 'true';
                const res = await maintainAllDomains(env, isManual);
                return new Response(JSON.stringify(res));
            }

        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
        return new Response('Not Found', { status: 404 });
    },

    async scheduled(event, env, ctx) {
        initConfig(env);
        ctx.waitUntil((async () => {
            await maintainAllDomains(env, false);
        })());
    }
};

// ========== 核心函数 ==========

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
    
    if (input.startsWith('txt@')) {
        const domain = input.substring(4);
        return { mode: 'TXT', domain, port: '443' };
    }
    
    if (input.startsWith('all@')) {
        const rest = input.substring(4);
        const { domain, port } = parseDomainPort(rest);
        return { mode: 'ALL', domain, port };
    }
    
    const { domain, port } = parseDomainPort(input);
    return { mode: 'A', domain, port };
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
        CONFIG.targets = [{ mode: 'A', domain: '', port: '443' }];
    }
    
    const sourceDomain = env.DOMAIN || '';
    if (sourceDomain) {
        const { domain, port } = parseDomainPort(sourceDomain);
        CONFIG.sourceDomain = domain;
        CONFIG.sourceDomainPort = port;
    }
    
    CONFIG.minActive = parseInt(env.MIN_ACTIVE) || 3;
    CONFIG.tgToken = env.TG_TOKEN || '';
    CONFIG.tgId = env.TG_ID || '';
    CONFIG.checkApi = env.CHECK_API || 'https://check.proxyip.cmliussss.net/check?proxyip=';
    CONFIG.dohApi = env.DOH_API || 'https://cloudflare-dns.com/dns-query';
    
    // 新增：IP信息查询配置
    CONFIG.ipInfoEnabled = env.IP_INFO_ENABLED === 'true';
    CONFIG.ipInfoApi = env.IP_INFO_API || 'http://ip-api.com/json';
    
    if (request) {
        const url = new URL(request.url);
        CONFIG.projectUrl = `${url.protocol}//${url.host}`;
    }
}

function cleanIPList(text) {
    if (!text) return '';
    
    const set = new Set();
    const lines = text.split('\n');
    
    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;
        
        let match = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/);
        if (match) {
            set.add(`${match[1]}:${match[2]}`);
            continue;
        }
        
        match = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})：(\d+)$/);
        if (match) {
            set.add(`${match[1]}:${match[2]}`);
            continue;
        }
        
        const parts = line.split(/\s+/);
        if (parts.length === 2) {
            const ip = parts[0].trim();
            const port = parts[1].trim();
            
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && /^\d+$/.test(port)) {
                set.add(`${ip}:${port}`);
                continue;
            }
        }
        
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(line)) {
            set.add(`${line}:443`);
            continue;
        }
        
        const complexMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\D+(\d+)/);
        if (complexMatch) {
            set.add(`${complexMatch[1]}:${complexMatch[2]}`);
        }
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
            headers: { 'accept': 'application/dns-json' }
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
            headers: { 'accept': 'application/dns-json' }
        });
        const d = await r.json();
        
        if (!d.Answer || d.Answer.length === 0) {
            return { raw: '', ips: [] };
        }
        
        const raw = d.Answer[0].data.replace(/^"|"$/g, '');
        const ips = raw.split(',').map(ip => ip.trim()).filter(ip => ip);
        
        return { raw, ips };
    } catch (e) {
        console.error('DNS TXT resolution failed:', e);
        return { raw: '', ips: [] };
    }
}

/**
 * 新增：查询IP归属地信息
 * 使用 ip-api.com 免费API（45次/分钟）
 */
async function getIPInfo(ip) {
    if (!CONFIG.ipInfoEnabled) {
        return null;
    }
    
    try {
        // 清理IP格式（移除方括号）
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
        txtRecords: []
    };
    
    if (target.mode === 'A' || target.mode === 'ALL') {
        const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=A`);
        if (records) {
            result.aRecords = await Promise.all(records.map(async r => {
                const addr = `${r.content}:${target.port}`;
                const c = await checkProxyIP(addr);
                
                // 新增：查询IP信息（如果启用）
                let ipInfo = null;
                if (CONFIG.ipInfoEnabled) {
                    ipInfo = await getIPInfo(r.content);
                }
                
                return {
                    id: r.id,
                    ip: r.content,
                    port: target.port,
                    success: c.success,
                    colo: c.colo || 'N/A',
                    time: c.responseTime || '-',
                    ipInfo: ipInfo  // 新增字段
                };
            }));
        }
    }
    
    if (target.mode === 'TXT' || target.mode === 'ALL') {
        const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=TXT`);
        if (records && records.length > 0) {
            const txtContent = records[0].content;
            const ips = txtContent.split(',').map(ip => ip.trim()).filter(ip => ip);
            
            const txtChecks = await Promise.all(ips.map(async addr => {
                const c = await checkProxyIP(addr);
                
                // 新增：查询IP信息（如果启用）
                const ipOnly = addr.split(':')[0];
                let ipInfo = null;
                if (CONFIG.ipInfoEnabled) {
                    ipInfo = await getIPInfo(ipOnly);
                }
                
                return {
                    ip: addr,
                    success: c.success,
                    colo: c.colo || 'N/A',
                    time: c.responseTime || '-',
                    ipInfo: ipInfo  // 新增字段
                };
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
        return d.result;
    } catch (e) {
        console.error('Cloudflare API error:', e);
        return null;
    }
}

async function getCandidateIPs(env, addLog) {
    let candidates = [];
    
    if (CONFIG.sourceDomain) {
        addLog(`🔍 待解析域名: ${CONFIG.sourceDomain}`);
        const ips = await resolveDomain(CONFIG.sourceDomain);
        if (ips.length > 0) {
            ips.forEach(ip => {
                candidates.push(`${ip}:${CONFIG.sourceDomainPort}`);
            });
            addLog(`  找到 ${ips.length} 个IP`);
        }
    }
    
    const pool = await env.IP_DATA.get('pool') || '';
    if (pool) {
        const poolList = pool.split('\n').filter(l => l.trim());
        addLog(`📦 IP库: ${poolList.length} 个`);
        candidates = candidates.concat(poolList);
    }
    
    return candidates;
}

async function maintainARecords(env, target, addLog, report) {
    addLog(`📋 维护A记录: ${target.domain}:${target.port}`);
    
    const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=A`) || [];
    addLog(`当前A记录: ${records.length} 条`);
    
    let activeIPs = [];
    let poolRaw = await env.IP_DATA.get('pool') || '';
    let poolList = poolRaw.split('\n').filter(l => l.trim());
    
    for (const r of records) {
        const addr = `${r.content}:${target.port}`;
        const c = await checkProxyIP(addr);
        
        // 新增：查询IP信息（如果启用）
        let ipInfo = null;
        if (CONFIG.ipInfoEnabled) {
            ipInfo = await getIPInfo(r.content);
        }
        
        report.checkDetails.push({
            ip: addr,
            status: c.success ? '✅ 活跃' : '❌ 失效',
            colo: c.colo || 'N/A',
            time: c.responseTime || '-',
            ipInfo: ipInfo
        });
        
        if (c.success) {
            activeIPs.push(r.content);
            
            // 增强日志：包含IP归属地信息
            let logMsg = `  ✅ ${addr} - ${c.colo} (${c.responseTime}ms)`;
            if (ipInfo) {
                logMsg += ` | ${ipInfo.country} ${ipInfo.asn} ${ipInfo.isp}`;
            }
            addLog(logMsg);
        } else {
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${r.id}`, 'DELETE');
            report.removed.push({ ip: r.content, reason: '检测失效' });
            poolList = poolList.filter(p => p !== addr);
            report.poolRemoved++;
            addLog(`  ❌ ${addr} - 失效已删除`);
        }
    }
    
    report.beforeActive = activeIPs.length;
    
    if (activeIPs.length < CONFIG.minActive) {
        addLog(`需补充: ${CONFIG.minActive - activeIPs.length} 个`);
        
        const candidates = await getCandidateIPs(env, addLog);
        
        for (const item of candidates) {
            if (activeIPs.length >= CONFIG.minActive) break;
            
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
                
                // 新增：查询新添加IP的信息
                let ipInfo = null;
                if (CONFIG.ipInfoEnabled) {
                    ipInfo = await getIPInfo(ip);
                }
                
                report.added.push({
                    ip: ip,
                    colo: checkResult.colo || 'N/A',
                    time: checkResult.responseTime || '-',
                    ipInfo: ipInfo
                });
                
                let logMsg = `  ✅ ${item} - ${checkResult.colo} (${checkResult.responseTime}ms)`;
                if (ipInfo) {
                    logMsg += ` | ${ipInfo.country} ${ipInfo.asn} ${ipInfo.isp}`;
                }
                addLog(logMsg);
            } else {
                poolList = poolList.filter(p => p !== item);
                report.poolRemoved++;
            }
        }
        
        await env.IP_DATA.put('pool', poolList.join('\n'));
        
        if (activeIPs.length < CONFIG.minActive) {
            report.poolExhausted = true;
        }
    } else {
        if (report.poolRemoved > 0) {
            await env.IP_DATA.put('pool', poolList.join('\n'));
        }
    }
    
    report.afterActive = activeIPs.length;
}

async function maintainTXTRecords(env, target, addLog, report) {
    addLog(`📝 维护TXT: ${target.domain}`);
    
    const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${target.domain}&type=TXT`);
    let currentIPs = [];
    let recordId = null;
    
    if (records && records.length > 0) {
        recordId = records[0].id;
        const txtContent = records[0].content;
        currentIPs = txtContent.split(',').map(ip => ip.trim()).filter(ip => ip);
        addLog(`当前TXT: ${currentIPs.length} 个`);
    }
    
    let validIPs = [];
    for (const addr of currentIPs) {
        const c = await checkProxyIP(addr);
        
        // 新增：查询IP信息
        const ipOnly = addr.split(':')[0];
        let ipInfo = null;
        if (CONFIG.ipInfoEnabled) {
            ipInfo = await getIPInfo(ipOnly);
        }
        
        report.checkDetails.push({
            ip: addr,
            status: c.success ? '✅ 活跃' : '❌ 失效',
            colo: c.colo || 'N/A',
            time: c.responseTime || '-',
            ipInfo: ipInfo
        });
        
        if (c.success) {
            validIPs.push(addr);
            
            let logMsg = `  ✅ ${addr} - ${c.colo} (${c.responseTime}ms)`;
            if (ipInfo) {
                logMsg += ` | ${ipInfo.country} ${ipInfo.asn} ${ipInfo.isp}`;
            }
            addLog(logMsg);
        } else {
            report.removed.push({ ip: addr, reason: '检测失效' });
        }
    }
    
    report.beforeActive = validIPs.length;
    
    if (validIPs.length < CONFIG.minActive) {
        const candidates = await getCandidateIPs(env, addLog);
        let poolList = (await env.IP_DATA.get('pool') || '').split('\n').filter(l => l.trim());
        
        for (const item of candidates) {
            if (validIPs.length >= CONFIG.minActive) break;
            if (validIPs.includes(item)) continue;
            
            const checkResult = await checkProxyIP(item);
            
            if (checkResult.success) {
                validIPs.push(item);
                
                const ipOnly = item.split(':')[0];
                let ipInfo = null;
                if (CONFIG.ipInfoEnabled) {
                    ipInfo = await getIPInfo(ipOnly);
                }
                
                report.added.push({
                    ip: item,
                    colo: checkResult.colo || 'N/A',
                    time: checkResult.responseTime || '-',
                    ipInfo: ipInfo
                });
                
                let logMsg = `  ✅ ${item} - ${checkResult.colo} (${checkResult.responseTime}ms)`;
                if (ipInfo) {
                    logMsg += ` | ${ipInfo.country} ${ipInfo.asn} ${ipInfo.isp}`;
                }
                addLog(logMsg);
            } else {
                poolList = poolList.filter(p => p !== item);
                report.poolRemoved++;
            }
        }
        
        await env.IP_DATA.put('pool', poolList.join('\n'));
        
        if (validIPs.length < CONFIG.minActive) {
            report.poolExhausted = true;
        }
    }
    
    const newContent = validIPs.join(',');
    const currentContent = currentIPs.join(',');
    
    if (newContent !== currentContent) {
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
    } else {
        addLog(`📝 TXT无变化，跳过更新`);
    }
    
    report.afterActive = validIPs.length;
}

async function maintainAllDomains(env, isManual = false) {
    const allReports = [];
    let globalPoolBefore = 0;
    let globalPoolAfter = 0;
    
    const poolRaw = await env.IP_DATA.get('pool') || '';
    globalPoolBefore = poolRaw ? poolRaw.split('\n').filter(l => l.trim()).length : 0;
    
    for (let i = 0; i < CONFIG.targets.length; i++) {
        const target = CONFIG.targets[i];
        
        const report = {
            target: target,
            domain: target.domain,
            mode: target.mode,
            port: target.port,
            beforeActive: 0,
            afterActive: 0,
            added: [],
            removed: [],
            poolRemoved: 0,
            poolExhausted: false,
            checkDetails: [],
            logs: []
        };
        
        const addLog = (m) => {
            const time = new Date().toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' });
            report.logs.push(`[${time}] ${m}`);
        };
        
        addLog(`🚀 开始维护: ${target.domain}`);
        
        if (target.mode === 'A') {
            await maintainARecords(env, target, addLog, report);
        } else if (target.mode === 'TXT') {
            await maintainTXTRecords(env, target, addLog, report);
        } else if (target.mode === 'ALL') {
            await maintainARecords(env, target, addLog, report);
            
            const txtReport = {
                ...report,
                beforeActive: 0,
                afterActive: 0,
                added: [],
                removed: [],
                checkDetails: [],
                logs: []
            };
            const addTxtLog = (m) => {
                const time = new Date().toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' });
                txtReport.logs.push(`[${time}] ${m}`);
            };
            await maintainTXTRecords(env, target, addTxtLog, txtReport);
            
            report.txtLogs = txtReport.logs;
            report.txtAdded = txtReport.added;
            report.txtRemoved = txtReport.removed;
            report.txtActive = txtReport.afterActive;
        }
        
        addLog(`✅ 完成: ${report.afterActive}/${CONFIG.minActive}`);
        allReports.push(report);
    }
    
    const poolAfterRaw = await env.IP_DATA.get('pool') || '';
    globalPoolAfter = poolAfterRaw ? poolAfterRaw.split('\n').filter(l => l.trim()).length : 0;
    
    const shouldNotify = isManual || 
        allReports.some(r => r.added.length > 0 || r.removed.length > 0) ||
        allReports.some(r => r.poolExhausted);
    
    if (shouldNotify) {
        await sendTG(allReports, globalPoolBefore, globalPoolAfter);
    }
    
    return {
        success: true,
        reports: allReports,
        poolBefore: globalPoolBefore,
        poolAfter: globalPoolAfter,
        notified: shouldNotify
    };
}

async function sendTG(reports, poolBefore, poolAfter) {
    if (!CONFIG.tgToken || !CONFIG.tgId) return;
    
    const modeLabel = { 'A': 'A记录', 'TXT': 'TXT记录', 'ALL': '双模式' };
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    
    let msg = `🔧 <b>DDNS 维护报告</b>\n`;
    msg += `━━━━━━━━━━━━━━━━━━\n`;
    msg += `⏰ <b>时间:</b> ${timestamp}\n\n`;
    
    reports.forEach((report, index) => {
        msg += `<b>${index + 1}. ${report.domain}</b> (${modeLabel[report.mode]}`;
        if (report.mode === 'A' || report.mode === 'ALL') {
            msg += ` · 端口${report.port}`;
        }
        msg += `)\n`;
        
        if (report.logs && report.logs.length > 0) {
            const keyLogs = report.logs.filter(log => 
                log.includes('当前') || 
                log.includes('✅') ||
                log.includes('已更新') ||
                log.includes('已创建') ||
                log.includes('完成')
            );
            keyLogs.forEach(log => {
                msg += `<code>${log}</code>\n`;
            });
        }
        
        if (report.mode === 'ALL' && report.txtLogs) {
            const txtKeyLogs = report.txtLogs.filter(log =>
                log.includes('当前TXT') ||
                log.includes('✅') ||
                log.includes('TXT已')
            );
            txtKeyLogs.forEach(log => {
                msg += `<code>${log}</code>\n`;
            });
        }
        
        msg += `\n`;
    });
    
    msg += `📦 <b>IP库存变化</b>\n`;
    msg += `   维护前: ${poolBefore} 个\n`;
    msg += `   维护后: ${poolAfter} 个\n`;
    const poolChange = poolAfter - poolBefore;
    if (poolChange !== 0) {
        msg += `   变化: ${poolChange > 0 ? '+' : ''}${poolChange}\n`;
    }
    
    const hasExhausted = reports.some(r => r.poolExhausted);
    if (hasExhausted) {
        msg += `\n⚠️ <b>警告：部分域名IP不足！</b>\n`;
    }
    
    if (CONFIG.projectUrl) {
        msg += `\n🔗 <b>管理面板:</b> ${CONFIG.projectUrl}\n`;
    }
    
    try {
        await fetch(`https://api.telegram.org/bot${CONFIG.tgToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: CONFIG.tgId,
                text: msg,
                parse_mode: 'HTML'
            })
        });
    } catch (e) {
        console.error('Telegram notification failed:', e);
    }
}

function renderHTML(C) {
    const targetsJson = JSON.stringify(C.targets);
    const settingsJson = JSON.stringify(GLOBAL_SETTINGS);
    const ipInfoEnabled = C.ipInfoEnabled;
    
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro v4.2 - IP管理面板</title>
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
        .feature-badge {
            display: inline-block;
            background: #34c759;
            color: white;
            padding: 2px 8px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 600;
            margin-left: 8px;
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
        .form-control {
            border-radius: 12px;
            background: #f5f5f7;
            border: 1px solid transparent;
            padding: 12px 16px;
        }
        .form-control:focus {
            background: #fff;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px rgba(0,122,255,0.1);
        }
        .ip-source-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
        }
        .ip-source-tab {
            flex: 1;
            padding: 10px;
            border-radius: 10px;
            background: #f5f5f7;
            border: 2px solid transparent;
            cursor: pointer;
            text-align: center;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s;
        }
        .ip-source-tab:hover {
            background: #e8e8ed;
        }
        .ip-source-tab.active {
            background: #e8f4ff;
            border-color: var(--primary);
            color: var(--primary);
        }
        .ip-source-content {
            display: none;
        }
        .ip-source-content.active {
            display: block;
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
        .ip-info-tag {
            display: inline-block;
            background: #e8f4ff;
            color: var(--primary);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            margin-left: 4px;
        }
    </style>
</head>
<body class="pb-5">

<div class="container hero">
    <h1>
        🌐 DDNS Pro 多域名管理
        <span class="version-badge">v4.2</span>
        ${ipInfoEnabled ? '<span class="feature-badge">🌍 IP归属地</span>' : ''}
    </h1>
    <div class="domain-selector">
        <select id="domain-select" class="form-select" onchange="switchDomain()">
            ${C.targets.map((t, i) => {
                const modeLabel = {'A': 'A记录', 'TXT': 'TXT', 'ALL': '双模式'};
                const label = `${t.domain} · ${modeLabel[t.mode]}${t.mode !== 'TXT' ? ' · ' + t.port : ''}`;
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
                <input type="text" id="manual-add-ip" class="form-control" placeholder="手动添加IP (如: 1.2.3.4)">
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
            <div class="card p-4">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <div>
                        <h6 class="m-0 fw-bold d-inline">📦 IP管理中心</h6>
                        <div class="config-info ms-2">
                            ⚙️ 并发: ${GLOBAL_SETTINGS.CONCURRENT_CHECKS} | 超时: ${GLOBAL_SETTINGS.CHECK_TIMEOUT}ms
                        </div>
                    </div>
                    <button class="btn btn-sm btn-outline-secondary" onclick="refreshPoolCount()">
                        <span id="pool-count">...</span> 个库存
                    </button>
                </div>
                
                <div class="ip-source-tabs">
                    <div class="ip-source-tab active" data-source="manual">📝 手动输入</div>
                    <div class="ip-source-tab" data-source="remote">🌐 远程TXT</div>
                    <div class="ip-source-tab" data-source="pool">📚 IP库</div>
                </div>
                
                <div id="source-manual" class="ip-source-content active">
                    <textarea id="ip-input-manual" class="form-control mb-2" rows="8" placeholder="每行一个，支持以下格式：
1.2.3.4:443
1.2.3.4 443
1.2.3.4	443
1.2.3.4"></textarea>
                    <div class="format-hint">
                        💡 <strong>支持从Excel/CSV直接复制粘贴</strong><br>
                        支持 IP:PORT | IP 空格 PORT | IP Tab PORT | IP (默认443端口)<br>
                        ⚠️ <strong>检测清洗只处理输入框中的IP，不影响库存</strong>
                    </div>
                </div>
                
                <div id="source-remote" class="ip-source-content">
                    <div class="input-group mb-3">
                        <input type="text" id="remote-url" class="form-control" placeholder="远程TXT文件URL">
                        <button class="btn btn-primary" onclick="loadRemoteUrl()">🔄 加载</button>
                    </div>
                    <textarea id="ip-input-remote" class="form-control mb-3" rows="8" placeholder="加载的IP..."></textarea>
                </div>
                
                <div id="source-pool" class="ip-source-content">
                    <button class="btn btn-outline-primary btn-sm w-100 mb-3" onclick="loadFromPool()">📂 加载库存</button>
                    <textarea id="ip-input-pool" class="form-control mb-3" rows="8" placeholder="库中IP..."></textarea>
                </div>
                
                <div class="row g-2">
                    <div class="col-6">
                        <button id="btn-check" class="btn btn-warning btn-sm w-100 text-white" onclick="batchCheck()">⚡ 检测清洗</button>
                    </div>
                    <div class="col-6">
                        <button class="btn btn-success btn-sm w-100" onclick="saveToPool()">💾 追加入库</button>
                    </div>
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
    let currentSource = 'manual';
    let abortController = null;
    
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
        
        const manualSection = document.getElementById('manual-add-section');
        if (target.mode === 'A' || target.mode === 'ALL') {
            manualSection.style.display = 'block';
        } else {
            manualSection.style.display = 'none';
        }
        
        refreshStatus();
    }
    
    document.querySelectorAll('.ip-source-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const source = this.dataset.source;
            document.querySelectorAll('.ip-source-tab').forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            document.querySelectorAll('.ip-source-content').forEach(c => c.classList.remove('active'));
            document.getElementById(\`source-\${source}\`).classList.add('active');
            currentSource = source;
        });
    });
    
    function getCurrentInput() {
        return document.getElementById(\`ip-input-\${currentSource}\`);
    }
    
    async function refreshPoolCount() {
        try {
            const r = await fetch('/api/get-pool?onlyCount=true').then(r => r.json());
            document.getElementById('pool-count').innerText = r.count;
        } catch (e) {}
    }
    
    async function loadFromPool() {
        log('📂 加载库存...', 'info');
        try {
            const r = await fetch('/api/get-pool').then(r => r.json());
            getCurrentInput().value = r.pool || '';
            document.getElementById('pool-count').innerText = r.count;
            log(\`✅ 成功: \${r.count} 个\`, 'success');
        } catch (e) {
            log(\`❌ 失败\`, 'error');
        }
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
                getCurrentInput().value = r.ips || '';
                log(\`✅ 成功: \${r.count} 个\`, 'success');
            } else {
                log(\`❌ 失败\`, 'error');
            }
        } catch (e) {
            log(\`❌ 出错\`, 'error');
        }
    }
    
    async function saveToPool() {
        const content = getCurrentInput().value;
        if (!content.trim()) {
            log('❌ 内容为空', 'error');
            return;
        }
        
        log('💾 追加入库中...', 'warn');
        try {
            const r = await fetch('/api/save-pool', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ pool: content })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ 成功: 总计 \${r.count} 个 (新增 \${r.added} 个)\`, 'success');
                document.getElementById('pool-count').innerText = r.count;
            }
        } catch (e) {
            log(\`❌ 失败\`, 'error');
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
        btn.textContent = '🛑 停止检测';
        btn.classList.remove('btn-warning');
        btn.classList.add('btn-danger');
        
        let valid = [], total = lines.length, checked = 0;
        const pg = document.getElementById('pg-bar');
        
        log(\`🚀 开始检测 \${total} 个IP (并发: \${SETTINGS.CONCURRENT_CHECKS})\`, 'warn');
        
        const chunkSize = SETTINGS.CONCURRENT_CHECKS;
        try {
            for (let i = 0; i < lines.length; i += chunkSize) {
                if (abortController.signal.aborted) break;
                
                const chunk = lines.slice(i, i + chunkSize);
                
                await Promise.all(chunk.map(async (line) => {
                    if (abortController.signal.aborted) return;
                    
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
                            signal: abortController.signal
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
                    
                    pg.style.width = (checked / total * 100) + '%';
                }));
            }
            
            if (!abortController.signal.aborted) {
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
            
            if ((data.mode === 'TXT' || data.mode === 'ALL') && data.txtRecords && data.txtRecords.length > 0) {
                const record = data.txtRecords[0];
                let html = '<h6 class="fw-bold mb-2 mt-3">📝 TXT记录内容</h6><div class="p-3 bg-light rounded-3">';
                record.ips.forEach(ip => {
                    html += \`<div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-white rounded">
                        <code>\${ip.ip}</code>
                        <div>
                            <span class="badge \${ip.success?'bg-success':'bg-danger'}">\${ip.success?'✅':'❌'} \${ip.colo} · \${ip.time}ms</span>
                            \${IP_INFO_ENABLED && ip.ipInfo ? formatIPInfo(ip.ipInfo) : ''}
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
            t.innerHTML = \`<tr><td colspan="\${colspan}" class="text-danger p-4">❌ 查询失败</td></tr>\`;
        }
    }
    
    async function manualAddIP() {
        const input = document.getElementById('manual-add-ip');
        const ip = input.value.trim();
        
        if (!ip) {
            log('❌ 请输入IP', 'error');
            return;
        }
        
        log(\`➕ 添加: \${ip}\`, 'info');
        
        try {
            const r = await fetch('/api/add-a-record', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ip, targetIndex: currentTargetIndex })
            }).then(r => r.json());
            
            if (r.success) {
                log(\`✅ 成功 - \${r.colo} (\${r.time}ms)\`, 'success');
                input.value = '';
                refreshStatus();
            } else {
                log(\`❌ 失败: \${r.error || '未知错误'}\`, 'error');
            }
        } catch (e) {
            log(\`❌ 出错\`, 'error');
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
                
                for (const ip of data.ips) {
                    await checkAndDisplayIP(ip, res);
                }
                return;
            }
            
            const isIP = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?$/.test(val);
            
            if (isIP) {
                log(\`🔌 直接检测: \${val}\`, 'info');
                const res = document.getElementById('lookup-results');
                res.innerHTML = '';
                await checkAndDisplayIP(val, res);
            } else {
                const data = await fetch(\`/api/lookup-domain?domain=\${encodeURIComponent(val)}\`).then(r => r.json());
                
                if (!data.ips || data.ips.length === 0) {
                    log(\`⚠️  域名无A记录\`, 'warn');
                    return;
                }
                
                log(\`📡 \${data.ips.length} 个IP (端口: \${data.port})\`, 'success');
                
                const res = document.getElementById('lookup-results');
                res.innerHTML = '';
                
                for (const ip of data.ips) {
                    const target = \`\${ip}:\${data.port}\`;
                    await checkAndDisplayIP(target, res);
                }
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
                
                // 如果启用了IP信息查询，获取并显示
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
            } else {
                info.innerHTML = '<span class="text-danger">❌ 失效</span>';
                log(\`  ❌ \${ip}\`, 'error');
            }
        } catch (e) {
            const info = document.getElementById(id);
            if (info) {
                info.innerHTML = '<span class="text-danger">❌ 出错</span>';
            }
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
    
    async function runMaintain() {
        log('🔧 启动维护...', 'warn');
        
        try {
            const r = await fetch('/api/maintain?manual=true').then(r => r.json());
            
            if (r.reports) {
                r.reports.forEach(report => {
                    log(\`\\n━━ \${report.domain} ━━\`, 'info');
                    if (report.logs) {
                        report.logs.forEach(msg => log(msg, 'info', true));
                    }
                });
            }
            
            log(\`✅ 维护完成\`, 'success');
            if (r.notified) {
                log(\`📱 已发送TG通知\`, 'info');
            } else {
                log(\`📱 无变化，未发送通知\`, 'info');
            }
            refreshStatus();
            refreshPoolCount();
        } catch (e) {
            log(\`❌ 失败: \${e.message}\`, 'error');
        }
    }
    
    window.addEventListener('DOMContentLoaded', () => {
        log('🚀 系统就绪', 'success');
        log(\`⚙️  配置: 并发\${SETTINGS.CONCURRENT_CHECKS} | 超时\${SETTINGS.CHECK_TIMEOUT}ms\`, 'info');
        if (IP_INFO_ENABLED) {
            log('🌍 IP归属地查询: 已启用', 'info');
        }
        switchDomain();
        refreshPoolCount();
    });
</script>
</body>
</html>
    `;
}
