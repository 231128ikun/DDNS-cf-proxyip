// ProxyIP 监控管理系统 
// KV 命名空间绑定名称: PROXYIP_STORE

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return handleCORS();

    // 1. 静态路由
    if (url.pathname === '/' || url.pathname === '/admin') {
      return new Response(getHTML(url.pathname), { 
        headers: { 'Content-Type': 'text/html;charset=UTF-8' } 
      });
    }

    // 2. 鉴权校验
    const config = await getConfig(env);
    const clientPwd = request.headers.get('x-password');
    // 定义敏感操作 API
    const isWrite = request.method === 'POST' || request.method === 'DELETE';
    const isAdminData = ['/api/config', '/api/ip-database', '/api/scan-summary'].includes(url.pathname);

    if (config.adminPassword && (isWrite || isAdminData)) {
      if (clientPwd !== config.adminPassword) {
        return jsonResponse({ error: 'AUTH_REQUIRED', message: '请在 /admin 登录' }, 401);
      }
    }

    try {
      if (url.pathname === '/api/config') return handleConfig(request, env);
      if (url.pathname === '/api/current-ips') return handleGetCurrentIPs(request, env);
      if (url.pathname === '/api/update-dns') return handleUpdateDNS(request, env);
      if (url.pathname === '/api/check') return handleCheck(request, env);
      if (url.pathname === '/api/ip-database') return handleIPDatabase(request, env);
      if (url.pathname === '/api/logs') return handleLogs(request, env);
      if (url.pathname === '/api/scan-summary') return handleScanSummary(request, env);
      if (url.pathname === '/api/maintenance') {
        ctx.waitUntil(this.runMaintenance(env, true));
        return jsonResponse({ success: true });
      }
    } catch (e) {
      return jsonResponse({ error: e.message }, 500);
    }
    return new Response('Not Found', { status: 404 });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(this.runMaintenance(env, false));
  },

  async runMaintenance(env, isManual = false) {
    const config = await getConfig(env);
    if (!config.cfApiKey) return;

    const start = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    await addLog(env, `[${isManual ? '手动' : '定时'}] 启动同步任务...`, "TASK");
    
    let report = {
      domain: config.cfDomain,
      port: config.targetPort,
      removed: [],
      added: [],
      onlineDetails: [],
      totalCandidate: 0,
      adminUrl: `https://${config.cfDomain}/admin`
    };

    try {
      let pool = [];
      const localDB = await env.PROXYIP_STORE.get('ip-database') || '';
      pool.push(...extractIPs(localDB));
      if (config.remoteApis) {
        for (const api of config.remoteApis.split(',')) {
          try {
            const res = await fetch(api.trim(), { signal: AbortSignal.timeout(5000) });
            pool.push(...extractIPs(await res.text()));
          } catch (e) {}
        }
      }
      if (config.remoteDomains) {
        for (const dom of config.remoteDomains.split(',')) {
          pool.push(...(await resolveDomain(dom.trim())));
        }
      }
      pool = [...new Set(pool)];
      report.totalCandidate = pool.length;

      const currentRecords = await fetchDNSRecords(config);
      const healthyIPs = [];
      for (const record of currentRecords) {
        const res = await checkProxyIP(`${record.content}:${config.targetPort}`, config.checkBackends);
        if (res.success) {
          healthyIPs.push(record.content);
          report.onlineDetails.push({ ip: record.content, ms: res.responseTime, loc: res.colo });
        } else {
          await deleteDNSRecord(record.id, config);
          report.removed.push(record.content);
        }
        await sleep(200);
      }

      const needed = Math.max(0, config.minActiveIPs - healthyIPs.length);
      if (needed > 0) {
        const poolFiltered = pool.filter(ip => !healthyIPs.includes(ip));
        let count = 0;
        for (const ip of poolFiltered) {
          if (count >= needed) break;
          const res = await checkProxyIP(`${ip}:${config.targetPort}`, config.checkBackends);
          if (res.success) {
            await addDNSRecord(ip, config);
            report.added.push(ip);
            report.onlineDetails.push({ ip: ip, ms: res.responseTime, loc: res.colo });
            count++;
          }
          await sleep(200);
        }
      }

      await addLog(env, `同步结束: 在线${report.onlineDetails.length}`, "TASK");
      await sendTGNotification(buildTGMsg(report, isManual, start), config);
    } catch (e) {
      await addLog(env, `同步异常: ${e.message}`, "ERROR");
    }
  }
};

// --- 后端核心逻辑 ---

async function getConfig(env) {
  const kvConfig = await env.PROXYIP_STORE.get('config', { type: 'json' }) || {};
  return {
    cfMail: kvConfig.cfMail || env.CF_MAIL || '',
    cfDomain: kvConfig.cfDomain || env.CF_DOMAIN || '',
    cfZoneId: kvConfig.cfZoneId || env.CF_ZONEID || '',
    cfApiKey: kvConfig.cfApiKey || env.CF_KEY || '',
    targetPort: kvConfig.targetPort || env.TARGET_PORT || '50001',
    minActiveIPs: parseInt(kvConfig.minActiveIPs || env.MIN_ACTIVE_IPS || '3'),
    checkBackends: kvConfig.checkBackends || env.CHECK_BACKENDS || 'https://check.dwb.pp.ua/check',
    tgBotToken: kvConfig.tgBotToken || env.TG_TOKEN || '',
    tgChatId: kvConfig.tgChatId || env.TG_ID || '',
    adminPassword: kvConfig.adminPassword || env.ADMIN_PASSWORD || '',
    remoteApis: kvConfig.remoteApis || env.REMOTE_APIS || '',
    remoteDomains: kvConfig.remoteDomains || env.REMOTE_DOMAINS || ''
  };
}

function buildTGMsg(report, isManual, startTime) {
  const nodes = report.onlineDetails.map((d, i) => `${i+1}. \`${d.ip}\` | ${d.ms}ms | ${d.loc}`).join('\n');
  return `
🚀 *ProxyIP 维护报告*
---------------------------
🌐 域名: \`${report.domain}:${report.port}\`
🕒 时间: \`${startTime}\` (\`${isManual ? '手动' : '定时'}\`)
✅ 在线: \`${report.onlineDetails.length}\` | 🔴 移除: \`${report.removed.length}\`
➕ 补全: \`${report.added.length}\` | 📦 库量: \`${report.totalCandidate}\`

*活跃列表:*
${nodes || '⚠️ 无活跃节点'}
---------------------------
🔗 [进入管理面板](${report.adminUrl})
  `;
}

async function resolveDomain(domain) {
  const ips = [];
  try {
    for (const type of ['A', 'AAAA']) {
      const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`, { headers: { 'accept': 'application/dns-json' } });
      const data = await resp.json();
      if (data.Answer) data.Answer.forEach(a => ips.push(a.data));
    }
  } catch (e) {}
  return ips;
}

function extractIPs(text) {
  const v4 = /((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}/g;
  const v6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})/g;
  return [...new Set([...(text.match(v4) || []), ...(text.match(v6) || [])])];
}

async function addLog(env, msg, type = "INFO") {
  let logs = await env.PROXYIP_STORE.get('system-logs', { type: 'json' }) || [];
  logs.unshift({ t: new Date().toLocaleString('zh-CN'), m: msg, y: type });
  await env.PROXYIP_STORE.put('system-logs', JSON.stringify(logs.slice(0, 50)));
}

async function handleLogs(request, env) {
  if (request.method === 'DELETE') { await env.PROXYIP_STORE.put('system-logs', '[]'); return jsonResponse({ success: true }); }
  return jsonResponse(await env.PROXYIP_STORE.get('system-logs', { type: 'json' }) || []);
}

async function handleScanSummary(request, env) {
  if (request.method === 'POST') {
    await env.PROXYIP_STORE.put('last-scan-summary', JSON.stringify(await request.json()));
    return jsonResponse({ success: true });
  }
  return jsonResponse(await env.PROXYIP_STORE.get('last-scan-summary', { type: 'json' }) || {});
}

async function handleConfig(request, env) {
  if (request.method === 'GET') {
    const config = await getConfig(env);
    const safe = { ...config };
    ['cfApiKey', 'tgBotToken', 'adminPassword'].forEach(k => { if (safe[k]) safe[k] = "HASH_SET"; });
    return jsonResponse(safe);
  }
  const data = await request.json();
  const old = await getConfig(env);
  ['cfApiKey', 'tgBotToken', 'adminPassword'].forEach(k => { if (data[k] === "HASH_SET") data[k] = old[k]; });
  await env.PROXYIP_STORE.put('config', JSON.stringify(data));
  return jsonResponse({ success: true });
}

async function handleIPDatabase(request, env) {
  if (request.method === 'GET') return jsonResponse({ data: await env.PROXYIP_STORE.get('ip-database') || '' });
  await env.PROXYIP_STORE.put('ip-database', (await request.json()).data);
  return jsonResponse({ success: true });
}

async function checkProxyIP(proxyip, backends = "") {
  const list = backends.split(',').map(b => b.trim()).filter(b=>b);
  const backend = list[Math.floor(Math.random() * list.length)] || 'https://check.dwb.pp.ua/check';
  try {
    const res = await fetch(`${backend}?proxyip=${proxyip}`, { signal: AbortSignal.timeout(6000) });
    return await res.json();
  } catch (e) { return { success: false, message: 'TIMEOUT' }; }
}

async function handleCheck(request, env) {
  const { target } = Object.fromEntries(new URL(request.url).searchParams);
  const config = await getConfig(env);
  return jsonResponse(await checkProxyIP(target, config.checkBackends));
}

async function fetchDNSRecords(config) {
  const url = `https://api.cloudflare.com/client/v4/zones/${config.cfZoneId}/dns_records?name=${config.cfDomain}&type=A`;
  const res = await fetch(url, { headers: { 'X-Auth-Email': config.cfMail, 'Authorization': `Bearer ${config.cfApiKey}` } });
  const data = await res.json();
  return data.success ? data.result : [];
}

async function addDNSRecord(ip, config) {
  await fetch(`https://api.cloudflare.com/client/v4/zones/${config.cfZoneId}/dns_records`, {
    method: 'POST',
    headers: { 'X-Auth-Email': config.cfMail, 'Authorization': `Bearer ${config.cfApiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'A', name: config.cfDomain, content: ip, ttl: 60, proxied: false })
  });
}

async function deleteDNSRecord(id, config) {
  await fetch(`https://api.cloudflare.com/client/v4/zones/${config.cfZoneId}/dns_records/${id}`, {
    method: 'DELETE',
    headers: { 'X-Auth-Email': config.cfMail, 'Authorization': `Bearer ${config.cfApiKey}` }
  });
}

async function handleGetCurrentIPs(request, env) {
  const config = await getConfig(env);
  if (!config.cfApiKey) return jsonResponse({ ips: [] });
  return jsonResponse({ ips: await fetchDNSRecords(config) });
}

async function handleUpdateDNS(request, env) {
  const { remove, add } = await request.json();
  const config = await getConfig(env);
  if (remove) for (const item of remove) if (item.id) await deleteDNSRecord(item.id, config);
  if (add) for (const item of add) await addDNSRecord(item.ip, config);
  return jsonResponse({ success: true });
}

async function sendTGNotification(text, config) {
  if (!config.tgBotToken || !config.tgChatId) return;
  await fetch(`https://api.telegram.org/bot${config.tgBotToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: config.tgChatId, text: text, parse_mode: 'Markdown' })
  });
}

function handleCORS() {
  return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// --- 前端 HTML 构造 ---

function getHTML(path) {
  const isAdmin = path === '/admin';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>ProxyIP/DDNS Pro Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .active-tab { border-bottom: 3px solid #3b82f6; color: #3b82f6; }
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-thumb { background: #334155; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
    .scan-pulse { animation: pulse 2s infinite; }
  </style>
</head>
<body class="bg-slate-950 text-slate-200">
  <div class="max-w-5xl mx-auto p-4 md:p-8">
    <header class="flex justify-between items-center mb-8">
      <div>
        <h1 class="text-3xl font-black text-blue-500 italic">PROXY-DDNS PRO</h1>
        <p class="text-[10px] text-slate-500 uppercase tracking-widest font-bold">${isAdmin ? 'ADMIN CONSOLE' : 'PUBLIC DASHBOARD'}</p>
      </div>
      <div class="flex gap-2">
        ${isAdmin ? `
          <button onclick="runMaintenance()" id="m-btn" class="bg-blue-600 px-6 py-2 rounded-xl text-sm font-bold transition">一键维护</button>
          <button onclick="logout()" class="bg-slate-800 px-4 py-2 rounded-xl text-sm">退出</button>
        ` : `
          <button onclick="location.href='/admin'" class="bg-blue-600 px-6 py-2 rounded-xl text-sm font-bold shadow-xl shadow-blue-900/40">管理后台</button>
        `}
      </div>
    </header>

    ${isAdmin ? `
      <div id="login-overlay" class="hidden fixed inset-0 bg-slate-950 z-50 flex items-center justify-center p-4">
        <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 w-full max-w-sm shadow-2xl text-center">
          <h2 class="text-xl font-bold text-blue-500 mb-6 underline">IDENTITY VERIFICATION</h2>
          <input id="login-pwd" type="password" placeholder="请输入管理密码" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl mb-4 text-center font-mono outline-none focus:border-blue-500">
          <button onclick="doLogin()" class="w-full bg-blue-600 py-3 rounded-xl font-bold">验证权限</button>
        </div>
      </div>
    ` : ''}

    <nav class="flex gap-6 border-b border-slate-900 mb-8 text-sm font-bold overflow-x-auto whitespace-nowrap">
      <button onclick="setTab('dashboard')" class="pb-3 tab-btn" id="btn-dashboard">仪表盘</button>
      ${isAdmin ? `
        <button onclick="setTab('database')" class="pb-3 tab-btn" id="btn-database">IP 库 <span id="scan-badge" class="hidden scan-pulse text-[8px] bg-blue-600 px-1 rounded ml-1">SCANNING</span></button>
        <button onclick="setTab('tools')" class="pb-3 tab-btn" id="btn-tools">诊断/测试</button>
        <button onclick="setTab('config')" class="pb-3 tab-btn" id="btn-config">系统设置</button>
      ` : ''}
      <button onclick="setTab('logs')" class="pb-3 tab-btn" id="btn-logs">运行日志</button>
    </nav>
    <div id="content"></div>
  </div>

  <script>
    let state = { config:{}, currentIPs:[], db:'', logs:[], activeTab:'dashboard', isScanning: false, scanResults: [], scanIndex: 0, scanTotal: 0, lastScan: {}, isAdmin: ${isAdmin} };

    function logout() { localStorage.removeItem('admin_pwd'); location.href='/'; }
    function doLogin() { localStorage.setItem('admin_pwd', document.getElementById('login-pwd').value); document.getElementById('login-overlay').classList.add('hidden'); refreshData(); }

    async function api(path, method='GET', body=null) {
      const pwd = localStorage.getItem('admin_pwd') || '';
      const opts = { method, headers: { 'x-password': pwd, 'Content-Type': 'application/json' } };
      if(body) opts.body = JSON.stringify(body);
      const res = await fetch(path, opts);
      if(res.status === 401 && state.isAdmin) { document.getElementById('login-overlay').classList.remove('hidden'); return null; }
      return res.json();
    }

    async function setTab(tab) { state.activeTab = tab; document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active-tab', b.id === 'btn-' + tab)); render(); }

    async function refreshData() {
      state.config = (await api('/api/config')) || {};
      state.currentIPs = (await api('/api/current-ips'))?.ips || [];
      state.logs = await api('/api/logs') || [];
      state.lastScan = await api('/api/scan-summary') || {};
      if(state.isAdmin) state.db = (await api('/api/ip-database'))?.data || '';
      render();
    }

    async function runMaintenance() {
      document.getElementById('m-btn').innerText = '执行中...';
      await api('/api/maintenance');
      alert('已在后台同步，请查看日志或 TG');
      document.getElementById('m-btn').innerText = '一键维护';
    }

    async function startScan() {
      if(state.isScanning) return;
      const ips = [...new Set(state.db.split(/[\\n,\\s]+/).filter(i => i && !i.startsWith('#')))];
      state.scanTotal = ips.length; state.scanIndex = 0; state.scanResults = []; state.isScanning = true;
      saveScanProgress(); doScan();
    }

    async function doScan() {
      const ips = [...new Set(state.db.split(/[\\n,\\s]+/).filter(i => i && !i.startsWith('#')))];
      document.getElementById('scan-badge')?.classList.remove('hidden');
      while(state.scanIndex < ips.length && state.isScanning) {
        const batch = ips.slice(state.scanIndex, state.scanIndex + 4);
        const results = await Promise.all(batch.map(ip => api('/api/check?target=' + ip + ':' + state.config.targetPort)));
        results.forEach((r, i) => { if(r) state.scanResults.push({ ip: batch[i], success: r.success, ms: r.responseTime, loc: r.colo }); });
        state.scanIndex += batch.length;
        saveScanProgress();
        if(state.activeTab === 'database') renderScanUI();
      }
      if(state.scanIndex >= ips.length) {
        state.isScanning = false;
        const valid = state.scanResults.filter(r => r.success);
        await api('/api/scan-summary', 'POST', { time: new Date().toLocaleString(), total: state.scanTotal, validCount: valid.length, avgMs: valid.length ? Math.round(valid.reduce((a,b)=>a+b.ms,0)/valid.length) : 0 });
        localStorage.removeItem('scan_progress'); document.getElementById('scan-badge')?.classList.add('hidden'); refreshData();
      }
    }

    function saveScanProgress() { localStorage.setItem('scan_progress', JSON.stringify({ index: state.scanIndex, total: state.scanTotal, results: state.scanResults, isScanning: state.isScanning })); }

    async function customTest() {
      const target = document.getElementById('test-target').value;
      const resDiv = document.getElementById('test-res-body');
      resDiv.innerText = '正在调测...';
      const r = await api('/api/check?target=' + target);
      resDiv.innerText = JSON.stringify(r, null, 2);
      if(r?.success) {
        document.getElementById('test-tools-extra').innerHTML = '<div class="flex gap-2 mt-4"><button onclick="addIpToDb(\\''+target.split(':')[0]+'\\')" class="bg-blue-900/40 text-blue-400 px-4 py-2 rounded-xl text-xs">加入本地 IP 库</button><button onclick="addIpToDns(\\''+target.split(':')[0]+'\\')" class="bg-green-900/40 text-green-400 px-4 py-2 rounded-xl text-xs">直接解析到域名</button></div>';
      }
    }

    async function addIpToDb(ip) { state.db = ip + '\\n' + state.db; await api('/api/ip-database', 'POST', { data: state.db }); alert('已添加至库'); }
    async function addIpToDns(ip) { await api('/api/update-dns', 'POST', { add: [{ip}] }); alert('已发起解析'); refreshData(); }

    async function cleanInvalid() {
      if(!confirm('清理库中失效 IP？')) return;
      state.db = state.scanResults.filter(r => r.success).map(r => r.ip).join('\\n');
      await api('/api/ip-database', 'POST', { data: state.db });
      refreshData();
    }

    async function saveConfig() {
      const body = {};
      ['adminPassword','cfMail','cfDomain','cfZoneId','cfApiKey','targetPort','minActiveIPs','checkBackends','tgBotToken','tgChatId','remoteApis','remoteDomains'].forEach(f => {
        const el = document.getElementById('c-'+f); if(el) body[f] = el.value;
      });
      await api('/api/config', 'POST', body); alert('配置已应用'); refreshData();
    }

    function deduplicate() { 
      const ips = [...document.getElementById('db-area').value.matchAll(/((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}/g)].map(m=>m[0]);
      document.getElementById('db-area').value = [...new Set(ips)].join('\\n');
    }

    function renderScanUI() {
      const div = document.getElementById('scan-res'); if(!div) return;
      div.innerHTML = '<div class="flex justify-between text-blue-400 mb-4 border-b border-blue-900 pb-2 text-xs"><span>进度: '+state.scanIndex+'/'+state.scanTotal+'</span><span>有效: '+state.scanResults.filter(r=>r.success).length+'</span></div>';
      state.scanResults.slice(-20).forEach(r => {
        div.innerHTML += '<div class="flex justify-between text-[10px] mb-1 font-mono '+(r.success?'text-slate-400':'text-red-900/50')+'"><span>'+r.ip+'</span><span>'+(r.success?r.loc+'|'+r.ms+'ms':'FAIL')+'</span></div>';
      });
      div.scrollTop = div.scrollHeight;
    }

    function render() {
      const c = document.getElementById('content');
      if(state.activeTab === 'dashboard') {
        c.innerHTML = '<div class="grid md:grid-cols-2 gap-6 mb-8"><div class="bg-slate-900 p-6 rounded-3xl border border-slate-800"><h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">监控中心</h3><div class="text-2xl font-black text-blue-400 font-mono">'+(state.config.cfDomain||'未配置')+'</div><div class="text-[10px] text-slate-500 mt-2 uppercase font-bold tracking-widest">Port: '+state.config.targetPort+' | Goal: '+state.config.minActiveIPs+'</div></div><div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 flex justify-between items-center text-center"><div class="flex-1 border-r border-slate-800"><h3 class="text-[9px] text-slate-500 uppercase">当前在线</h3><div class="text-3xl font-black">'+state.currentIPs.length+'</div></div><div class="flex-1 px-2"><h3 class="text-[9px] text-slate-500 uppercase">最近扫描有效</h3><div class="text-3xl font-black text-blue-500">'+(state.lastScan.validCount||0)+'</div></div></div></div><div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden shadow-2xl"><div class="p-6 border-b border-slate-800 font-bold flex justify-between items-center"><span>Cloudflare A 记录列表</span><button onclick="refreshData()" class="text-xs text-blue-500 font-bold uppercase tracking-widest">刷新</button></div><div class="p-4 space-y-2">'+state.currentIPs.map(ip => '<div class="flex justify-between items-center bg-slate-950 p-4 rounded-2xl border border-slate-900"><div class="font-mono text-sm">'+ip.content+'</div>'+(state.isAdmin ? '<button onclick="deleteIP(\\''+ip.id+'\\')" class="text-xs text-slate-600 hover:text-red-500">移除</button>' : '<div class="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_8px_#22c55e]"></div>')+'</div>').join('')+'</div></div>';
      } else if(state.activeTab === 'database' && state.isAdmin) {
        c.innerHTML = '<div class="grid md:grid-cols-2 gap-6"><div class="bg-slate-900 p-6 rounded-3xl border border-slate-800"><div class="flex justify-between mb-4"><h3 class="text-xs font-bold uppercase text-slate-500">本地数据源</h3><button onclick="deduplicate()" class="text-[10px] text-blue-500 font-bold">去重</button></div><textarea id="db-area" class="w-full h-80 bg-slate-950 border border-slate-800 p-4 rounded-2xl font-mono text-[10px] outline-none">'+state.db+'</textarea><button onclick="saveDB()" class="w-full mt-4 bg-slate-800 py-3 rounded-xl text-sm font-bold">同步</button></div><div class="flex flex-col gap-6"><div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 flex-1 flex flex-col min-h-[300px]"><div class="flex gap-2 mb-4"><button onclick="startScan()" class="flex-1 bg-indigo-600 py-2 rounded-xl text-xs font-bold">启动扫描</button><button onclick="state.isScanning=false" class="bg-slate-800 px-4 rounded-xl text-xs font-bold">停止</button><button onclick="cleanInvalid()" class="bg-red-900/20 text-red-500 px-4 rounded-xl text-xs font-bold">清理失效</button></div><div id="scan-res" class="flex-1 bg-black/40 p-4 rounded-2xl font-mono text-[10px] overflow-y-auto min-h-[150px]"></div></div></div></div>';
      } else if(state.activeTab === 'config' && state.isAdmin) {
        c.innerHTML = '<div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 shadow-2xl space-y-8"><div class="grid md:grid-cols-2 gap-8 text-sm"><div class="space-y-4"><h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px] mb-4">基础配置</h4><div><label class="text-slate-500 block mb-1 font-bold">管理密码</label><input id="c-adminPassword" type="password" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.adminPassword||'')+'"></div><div><label class="text-slate-500 block mb-1">CF 邮箱</label><input id="c-cfMail" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.cfMail||'')+'"></div><div><label class="text-slate-500 block mb-1">监控域名</label><input id="c-cfDomain" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.cfDomain||'')+'"></div><div><label class="text-slate-500 block mb-1">Zone ID</label><input id="c-cfZoneId" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.cfZoneId||'')+'"></div><div><label class="text-slate-500 block mb-1">API Key</label><input id="c-cfApiKey" type="password" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.cfApiKey||'')+'"></div></div><div class="space-y-4"><h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px] mb-4">运行/通知</h4><div><label class="text-slate-500 block mb-1">远程 API 地址 (逗号分隔)</label><textarea id="c-remoteApis" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl h-20 text-[10px]">'+(state.config.remoteApis||'')+'</textarea></div><div><label class="text-slate-500 block mb-1">克隆域名</label><textarea id="c-remoteDomains" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl h-20 text-[10px]">'+(state.config.remoteDomains||'')+'</textarea></div><div class="grid grid-cols-2 gap-4"><div><label class="text-slate-500 block mb-1">检测端口</label><input id="c-targetPort" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.targetPort||'50001')+'"></div><div><label class="text-slate-500 block mb-1">最小活跃数</label><input id="c-minActiveIPs" type="number" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.minActiveIPs||3)+'"></div></div><div><label class="text-slate-500 block mb-1 font-bold">TG Token & ChatID</label><div class="flex gap-2"><input id="c-tgBotToken" type="password" class="flex-1 bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.tgBotToken||'')+'"><input id="c-tgChatId" class="w-32 bg-slate-950 border border-slate-800 p-3 rounded-xl" value="'+(state.config.tgChatId||'')+'"></div></div></div></div><button onclick="saveConfig()" class="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-2xl font-black text-white shadow-xl transition-all">保存配置信息</button></div>';
      } else if(state.activeTab === 'tools' && state.isAdmin) {
        c.innerHTML = '<div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 space-y-6"><h3 class="text-xl font-bold mb-2 italic tracking-tighter">Diagnostic Lab</h3><div class="flex gap-3"><input id="test-target" class="flex-1 bg-slate-950 border border-slate-800 p-4 rounded-2xl font-mono" placeholder="IP:PORT"><button onclick="customTest()" class="bg-blue-600 px-8 py-3 rounded-2xl font-bold active:scale-95">调测</button></div><div id="test-tools-extra"></div><div class="bg-black/50 p-6 rounded-2xl border border-slate-800 font-mono text-[11px] text-green-500 whitespace-pre-wrap min-h-[200px]" id="test-res-body">Waiting for signal...</div></div>';
      } else if(state.activeTab === 'logs') {
        c.innerHTML = '<div class="bg-slate-900 rounded-3xl border border-slate-800 shadow-2xl overflow-hidden"><div class="p-6 border-b border-slate-800 flex justify-between px-8"><span class="font-bold text-slate-500 uppercase text-xs tracking-tighter">Event Logs</span>' + (state.isAdmin ? '<button onclick="api(\\'/api/logs\\',\\'DELETE\\').then(refreshData)" class="text-[10px] text-red-500 font-bold uppercase underline">Clear</button>' : '') + '</div><div class="h-[500px] overflow-y-auto p-4 font-mono text-[10px] space-y-1">' + state.logs.map(l => '<div><span class="text-slate-600">['+l.t+']</span> <span class="'+(l.y==='ERROR'?'text-red-500':l.y==='TASK'?'text-blue-500':'text-slate-500')+' font-bold">['+l.y+']</span> '+l.m+'</div>').join('') + (state.logs.length === 0 ? '<p class="text-center text-slate-700 mt-20 italic">No events recorded.</p>' : '') + '</div></div>';
      }
    }

    async function deleteIP(id) { if(confirm('确认移除？')) { await api('/api/update-dns', 'POST', { remove:[{id}] }); refreshData(); } }
    async function saveDB() { await api('/api/ip-database', 'POST', { data: document.getElementById('db-area').value }); alert('同步完成'); refreshData(); }

    window.onload = async () => { await refreshData(); const saved = localStorage.getItem('scan_progress'); if(saved && state.isAdmin) { Object.assign(state, JSON.parse(saved)); if(state.isScanning) doScan(); } setInterval(refreshData, 30000); };
  </script>
</body>
</html>`;
}
