/**
 * DDNS Pro & Proxy IP Manager v1.0
 */

let CONFIG = {
    email: '', apiKey: '', zoneId: '', domain: '',
    targetPort: '443', // 默认 443
    minActive: 3,
    remoteUrls: [], tgToken: '', tgId: '',
    checkApi: 'https://check.dwb.pp.ua/check?proxyip=',
    dohApi: 'https://cloudflare-dns.com/dns-query'
};

export default {
    async fetch(request, env, ctx) {
        initConfig(env);
        const url = new URL(request.url);

        if (url.pathname === '/') return new Response(renderHTML(CONFIG), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

        try {
            if (url.pathname === '/api/get-pool') {
                const pool = await env.IP_DATA.get('pool') || '';
                const count = pool.trim() ? pool.trim().split('\n').length : 0;
                if (url.searchParams.get('onlyCount') === 'true') return new Response(JSON.stringify({ count }));
                return new Response(JSON.stringify({ pool, count }));
            }

            if (url.pathname === '/api/save-pool') {
                const body = await request.json();
                const cleaned = cleanIPList(body.pool || '', CONFIG.targetPort);
                await env.IP_DATA.put('pool', cleaned);
                return new Response(JSON.stringify({ success: true, count: cleaned ? cleaned.split('\n').length : 0 }));
            }

            if (url.pathname === '/api/sync-remote') {
                const count = await syncRemoteIPs(env);
                return new Response(JSON.stringify({ success: true, count }));
            }

            if (url.pathname === '/api/current-status') {
                const status = await getDomainStatus();
                return new Response(JSON.stringify(status));
            }

            if (url.pathname === '/api/lookup-domain') {
                const target = url.searchParams.get('domain');
                let [domain, port] = target.split(':');
                port = port || CONFIG.targetPort; 
                const ips = await resolveDomain(domain);
                return new Response(JSON.stringify({ ips, port }));
            }

            if (url.pathname === '/api/check-ip') {
                const res = await checkProxyIP(url.searchParams.get('ip'));
                return new Response(JSON.stringify(res));
            }

            if (url.pathname === '/api/delete-record') {
                await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${url.searchParams.get('id')}`, 'DELETE');
                return new Response(JSON.stringify({ success: true }));
            }

            if (url.pathname === '/api/maintain') {
                const res = await maintainDomain(env, true);
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
            await syncRemoteIPs(env);
            await maintainDomain(env, false);
        })());
    }
};

function cleanIPList(text, defaultPort) {
    if (!text) return '';
    const set = new Set();
    const regex = /(\d{1,3}(?:\.\d{1,3}){3})(?:[:\s\t]+(\d+))?/g;
    let m;
    while ((m = regex.exec(text)) !== null) {
        set.add(`${m[1]}:${m[2] || defaultPort}`);
    }
    return Array.from(set).join('\n');
}

async function syncRemoteIPs(env) {
    const old = await env.IP_DATA.get('pool') || '';
    let remote = "";
    for (const u of CONFIG.remoteUrls) {
        try {
            const r = await fetch(u, { signal: AbortSignal.timeout(8000) });
            if (r.ok) remote += await r.text() + "\n";
        } catch (e) {}
    }
    const combined = cleanIPList(old + "\n" + remote, CONFIG.targetPort);
    await env.IP_DATA.put('pool', combined);
    return combined ? combined.split('\n').length : 0;
}

function initConfig(env) {
    CONFIG.email = env.CF_MAIL || '';
    CONFIG.apiKey = env.CF_KEY || '';
    CONFIG.zoneId = env.CF_ZONEID || '';
    CONFIG.domain = env.CF_DOMAIN || '';
    CONFIG.targetPort = (env.TARGET_PORT || '443').toString();
    CONFIG.minActive = parseInt(env.MIN_ACTIVE) || 3;
    CONFIG.tgToken = env.TG_TOKEN || '';
    CONFIG.tgId = env.TG_ID || '';
    if (env.REMOTE_URLS) CONFIG.remoteUrls = env.REMOTE_URLS.split(',').map(u => u.trim());
}

async function resolveDomain(domain) {
    const r = await fetch(`${CONFIG.dohApi}?name=${domain}&type=A`, { headers: { 'accept': 'application/dns-json' } });
    const d = await r.json();
    return d.Answer ? d.Answer.map(a => a.data) : [];
}

async function getDomainStatus() {
    const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${CONFIG.domain}&type=A`);
    if (!records) return [];
    return await Promise.all(records.map(async r => {
        const addr = `${r.content}:${CONFIG.targetPort}`;
        const c = await checkProxyIP(addr);
        return { id: r.id, ip: r.content, success: c.success, colo: c.colo || 'N/A', time: c.responseTime || '-' };
    }));
}

async function checkProxyIP(ip) {
    const addr = ip.includes(':') ? ip : `${ip}:${CONFIG.targetPort}`;
    try {
        const r = await fetch(`${CONFIG.checkApi}${addr}`, { signal: AbortSignal.timeout(6000) });
        return await r.json();
    } catch (e) { return { success: false }; }
}

async function fetchCF(p, m = 'GET', body = null) {
    const i = { method: m, headers: { 'X-Auth-Email': CONFIG.email, 'Authorization': `Bearer ${CONFIG.apiKey}`, 'Content-Type': 'application/json' } };
    if (body) i.body = JSON.stringify(body);
    try {
        const r = await fetch(`https://api.cloudflare.com/client/v4${p}`, i);
        const d = await r.json();
        return d.result;
    } catch (e) { return null; }
}

async function maintainDomain(env, isManual) {
    let report = { added: [], removed: [], currentActive: 0, poolExhausted: false, logs: [] };
    const addLog = (m) => report.logs.push(`[${new Date().toLocaleTimeString()}] ${m}`);
    const records = await fetchCF(`/zones/${CONFIG.zoneId}/dns_records?name=${CONFIG.domain}&type=A`) || [];
    let activeIPs = [];
    let poolRaw = await env.IP_DATA.get('pool') || '';
    let poolList = poolRaw.split('\n').filter(l => l.trim());

    for (const r of records) {
        const addr = `${r.content}:${CONFIG.targetPort}`;
        const c = await checkProxyIP(addr);
        if (c.success) activeIPs.push(r.content);
        else { 
            await fetchCF(`/zones/${CONFIG.zoneId}/dns_records/${r.id}`, 'DELETE'); 
            report.removed.push(r.content);
            poolList = poolList.filter(p => p !== addr);
        }
    }

    if (activeIPs.length < CONFIG.minActive) {
        for (const item of poolList) {
            if (activeIPs.length >= CONFIG.minActive) break;
            const [ip, port] = item.split(':');
            if (activeIPs.includes(ip) || port !== CONFIG.targetPort) continue;
            if ((await checkProxyIP(item)).success) {
                await fetchCF(`/zones/${CONFIG.zoneId}/dns_records`, 'POST', { type: 'A', name: CONFIG.domain, content: ip, ttl: 60, proxied: false });
                activeIPs.push(ip); report.added.push(ip);
            } else {
                poolList = poolList.filter(p => p !== item);
            }
        }
        await env.IP_DATA.put('pool', poolList.join('\n'));
        if (activeIPs.length < CONFIG.minActive) report.poolExhausted = true;
    }
    report.currentActive = activeIPs.length;
    if (isManual || report.added.length > 0 || report.removed.length > 0 || report.poolExhausted) await sendTG(report);
    return report;
}

async function sendTG(r) {
    if (!CONFIG.tgToken || !CONFIG.tgId) return;
    const msg = `🛠️ DDNS: ${CONFIG.domain}\n活跃: ${r.currentActive}/${CONFIG.minActive}\n新增: ${r.added.length} | 移除: ${r.removed.length}`;
    await fetch(`https://api.telegram.org/bot${CONFIG.tgToken}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: CONFIG.tgId, text: msg }) });
}

function renderHTML(C) {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro Console</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root { --primary: #007aff; --bg: #f5f5f7; --card: #ffffff; --text: #1d1d1f; --secondary: #86868b; }
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; -webkit-font-smoothing: antialiased; letter-spacing: -0.01em; }
        .hero { padding: 40px 0 20px 0; text-align: left; }
        .hero h1 { font-size: 1.5rem; font-weight: 600; color: var(--secondary); margin-bottom: 8px; }
        .hero .domain-info { font-size: 2.2rem; font-weight: 700; color: var(--text); letter-spacing: -0.03em; }
        .card { border: none; border-radius: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.04); background: var(--card); margin-bottom: 24px; transition: transform 0.2s; }
        .console { background: #1c1c1e; color: #32d74b; height: 350px; overflow-y: auto; font-family: 'SF Mono', 'Fira Code', monospace; padding: 20px; border-radius: 16px; font-size: 13px; line-height: 1.6; }
        .table { margin: 0; }
        .table th { border: none; font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--secondary); padding: 15px; }
        .table td { border-top: 1px solid #f2f2f2; padding: 15px; vertical-align: middle; }
        .btn { border-radius: 12px; font-weight: 600; padding: 10px 20px; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); border: none; }
        .btn-primary { background: var(--primary); box-shadow: 0 4px 15px rgba(0,122,255,0.25); }
        .btn-primary:hover { transform: translateY(-1px); background: #0066d6; }
        .form-control { border-radius: 12px; background: #f5f5f7; border: 1px solid transparent; padding: 12px 16px; }
        .form-control:focus { background: #fff; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(0,122,255,0.1); }
        .status-pill { padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
        .badge-add { cursor: pointer; border-radius: 8px; font-size: 11px; font-weight: 600; }
        @media (max-width: 768px) { .hero .domain-info { font-size: 1.6rem; } .console { height: 260px; } }
    </style>
</head>
<body class="pb-5">

<div class="container hero">
    <h1>正在自动维护</h1>
    <div class="domain-info">${C.domain}<span style="color:var(--secondary); font-weight: 400;">:${C.targetPort}</span></div>
</div>

<div class="container">
    <div class="card p-3">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h6 class="m-0 fw-bold">解析实况</h6>
            <button class="btn btn-primary btn-sm" onclick="refreshStatus()">刷新状态</button>
        </div>
        <div class="table-responsive">
            <table class="table text-center">
                <thead><tr><th>IP地址</th><th>机房</th><th>延迟</th><th>状态</th><th>管理</th></tr></thead>
                <tbody id="status-table"></tbody>
            </table>
        </div>
    </div>

    <div class="row">
        <div class="col-lg-7">
            <div class="card p-4">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h6 class="m-0 fw-bold">IP 库池</h6>
                    <span class="small text-secondary">库存: <b id="pool-count" class="text-dark">...</b> <a href="javascript:refreshPoolCount()" class="text-decoration-none ms-2">刷新总数</a></span>
                </div>
                <textarea id="ip-pool" class="form-control mb-3" rows="8" placeholder="点击加载库详情..."></textarea>
                <div class="row g-2">
                    <div class="col-6"><button class="btn btn-outline-dark btn-sm w-100" onclick="loadPool()">📂 加载详情</button></div>
                    <div class="col-6"><button class="btn btn-primary btn-sm w-100" onclick="savePool()">✅ 保存并添加</button></div>
                </div>
                <button class="btn btn-light btn-sm w-100 mt-3 border" onclick="batchCheck()" style="background:#fff; color: #e67e22;">⚡ 极速洗库</button>
            </div>
            
            <div class="card p-4">
                <h6 class="mb-3 fw-bold">Check ProxyIP</h6>
                <div class="input-group mb-3">
                    <input type="text" id="lookup-dom" class="form-control" placeholder="输入域名或 域名:端口">
                    <button class="btn btn-info text-white" onclick="lookupDomain()">探测</button>
                </div>
                <div id="lookup-results" class="row g-2"></div>
            </div>
        </div>

        <div class="col-lg-5">
            <div class="card p-4 h-100">
                <h6 class="mb-3 fw-bold">系统日志</h6>
                <div id="log-window" class="console mb-3"></div>
                <div class="progress mb-4" style="height:14px; background: #f5f5f7; border-radius: 7px;">
                    <div id="pg-bar" class="progress-bar bg-primary" style="width:0%"></div>
                </div>
                <div class="d-grid gap-2">
                    <button class="btn btn-dark" onclick="runMaintain()">启动补齐维护</button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="syncRemote()">同步远程订阅库</button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    const log = (m, t='info') => {
        const w = document.getElementById('log-window'), c = { success: '#32d74b', error: '#ff453a', info: '#64d2ff', warn: '#ffd60a' };
        w.innerHTML += \`<div style="color:\${c[t]}">[\${new Date().toLocaleTimeString()}] \${m}</div>\`;
        w.scrollTop = w.scrollHeight;
    };

    async function refreshPoolCount() {
        const r = await fetch('/api/get-pool?onlyCount=true').then(r => r.json());
        document.getElementById('pool-count').innerText = r.count;
        log('刷新总数: ' + r.count);
    }

    async function loadPool() {
        log('载入详情中...');
        const r = await fetch('/api/get-pool').then(r => r.json());
        document.getElementById('ip-pool').value = r.pool || '';
        document.getElementById('pool-count').innerText = r.count;
        log('载入成功');
    }

    async function savePool() {
        log('正在保存...', 'warn');
        const r = await fetch('/api/save-pool', { method: 'POST', body: JSON.stringify({ pool: document.getElementById('ip-pool').value }) }).then(r => r.json());
        if(r.success) { log(\`入库成功: \${r.count}条\`, 'success'); document.getElementById('pool-count').innerText = r.count; }
    }

    async function batchCheck() {
        const l = document.getElementById('ip-pool').value.split('\\n').filter(i => i.trim());
        if(!l.length) return log('请先载入详情', 'error');
        let valid = [], ok = 0, checked = 0;
        const pg = document.getElementById('pg-bar');
        log(\`🚀 并发检测启动\`, 'warn');
        const chunkSize = 10;
        for (let i = 0; i < l.length; i += chunkSize) {
            const chunk = l.slice(i, i + chunkSize);
            await Promise.all(chunk.map(async (line) => {
                let item = line.trim().replace(/\\s+/g, ':');
                if(!item.includes(':')) item += ':443';
                const r = await fetch(\`/api/check-ip?ip=\${item}\`).then(r => r.json());
                checked++;
                if(r.success) { valid.push(item); ok++; log(\`✅ [\${item}]\`, 'success'); }
                else { log(\`❌ [\${item}]\`, 'error'); }
                pg.style.width = (checked / l.length * 100) + '%';
            }));
        }
        document.getElementById('ip-pool').value = valid.join('\\n');
        await savePool();
        log(\`洗库结束，活跃保留: \${ok}\`, 'success');
    }

    async function refreshStatus() {
        const t = document.getElementById('status-table');
        t.innerHTML = '<tr><td colspan="5" class="text-secondary p-4">查询中...</td></tr>';
        const d = await fetch('/api/current-status').then(r => r.json());
        t.innerHTML = d.map(r => \`
            <tr>
                <td class="fw-bold">\${r.ip}</td>
                <td><span class="badge bg-light text-dark">\${r.colo}</span></td>
                <td>\${r.time}ms</td>
                <td><span class="status-pill \${r.success?'text-success':'text-danger'}"><span class="dot \${r.success?'bg-success':'bg-danger'}"></span>\${r.success?'活跃':'失效'}</span></td>
                <td><a href="javascript:deleteRecord('\${r.id}')" class="text-danger text-decoration-none small fw-bold">移除</a></td>
            </tr>\`).join('') || '<tr><td colspan="5" class="p-4">无记录</td></tr>';
    }

    async function lookupDomain() {
        const val = document.getElementById('lookup-dom').value;
        if(!val) return;
        let [dom, port] = val.split(':');
        port = port || '443';
        log(\`解析: \${dom} (端口 \${port})\`);
        const { ips } = await fetch(\`/api/lookup-domain?domain=\${val}\`).then(r => r.json());
        const res = document.getElementById('lookup-results');
        res.innerHTML = '';
        await Promise.all(ips.map(async ip => {
            const id = 'ip-'+ip.replace(/\\./g,'-');
            const target = \`\${ip}:\${port}\`;
            res.innerHTML += \`<div class="col-6"><div class="border rounded-4 p-2 d-flex justify-content-between align-items-center bg-light"><span>\${target}</span><span id="\${id}" onclick="addToPool('\${target}')" class="badge-add bg-secondary text-white p-2">探测...</span></div></div>\`;
            const d = await fetch(\`/api/check-ip?ip=\${target}\`).then(r => r.json());
            const e = document.getElementById(id);
            e.className = 'badge-add p-2 text-white ' + (d.success ? 'bg-success' : 'bg-danger');
            e.innerText = d.success ? '追加' : '失效';
            log(\`探测: [\${target}] -> \${d.success?'有效':'失效'}\`);
        }));
    }

    function addToPool(v) {
        const b = document.getElementById('ip-pool');
        if(!b.value.includes(v)) { b.value += (b.value ? '\\n' : '') + v; log('追加: '+v, 'success'); }
    }

    async function deleteRecord(id) {
        if(confirm('移除？')) { await fetch(\`/api/delete-record?id=\${id}\`); refreshStatus(); }
    }

    async function syncRemote() { 
        log('同步库...', 'warn'); 
        const r = await fetch('/api/sync-remote').then(r => r.json()); 
        log('完成，库存: '+r.count, 'success'); 
        document.getElementById('pool-count').innerText = r.count;
    }

    async function runMaintain() { 
        log('启动任务...', 'warn'); 
        const r = await fetch('/api/maintain').then(r => r.json());
        r.logs.forEach(msg => log(msg));
        log(\`活跃解析: \${r.currentActive}\`, 'success'); 
        refreshStatus(); 
    }

    window.onload = () => { refreshStatus(); refreshPoolCount(); };
</script>
</body>
</html>
    `;
}
