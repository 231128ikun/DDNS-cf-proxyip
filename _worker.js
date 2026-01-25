// ProxyIP 监控管理系统 - 终极融合增强稳定版 V2
// KV 命名空间绑定名称: PROXYIP_STORE

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return handleCORS();

    try {
      if (url.pathname === '/' || url.pathname === '/index.html') {
        return new Response(getHTML(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      }

      if (url.pathname === '/api/config') return handleConfig(request, env);
      if (url.pathname === '/api/current-ips') return handleGetCurrentIPs(request, env);
      if (url.pathname === '/api/update-dns') return handleUpdateDNS(request, env);
      if (url.pathname === '/api/check') return handleCheck(request, env);
      if (url.pathname === '/api/ip-database') return handleIPDatabase(request, env);
      if (url.pathname === '/api/logs') return handleLogs(request, env);
      if (url.pathname === '/api/maintenance') {
        ctx.waitUntil(this.runMaintenance(env, true));
        return jsonResponse({ success: true, message: '手动更新任务已在后台启动' });
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

    const startTime = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    await addLog(env, `[${isManual ? '手动' : '定时'}] 启动维护任务...`, "TASK");
    
    let report = {
      domain: config.cfDomain,
      port: config.targetPort,
      removed: [],
      added: [],
      onlineDetails: [],
      totalCandidate: 0
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
          report.onlineDetails.push({ ip: record.content, ms: res.responseTime, loc: res.colo, asn: res.asn || 'N/A' });
        } else {
          await deleteDNSRecord(record.id, config);
          report.removed.push(record.content);
        }
        await sleep(200);
      }

      const needed = Math.max(0, config.minActiveIPs - healthyIPs.length);
      if (needed > 0) {
        const candidates = pool.filter(ip => !healthyIPs.includes(ip));
        let count = 0;
        for (const ip of candidates) {
          if (count >= needed) break;
          const res = await checkProxyIP(`${ip}:${config.targetPort}`, config.checkBackends);
          if (res.success) {
            await addDNSRecord(ip, config);
            report.added.push(ip);
            report.onlineDetails.push({ ip: ip, ms: res.responseTime, loc: res.colo, asn: res.asn || 'N/A' });
            count++;
          }
          await sleep(200);
        }
      }

      await addLog(env, `任务完成: 在线${report.onlineDetails.length}，移除${report.removed.length}`, "TASK");
      await sendTGNotification(buildTGMsg(report, isManual, startTime), config);

    } catch (e) {
      await addLog(env, `维护异常: ${e.message}`, "ERROR");
    }
  }
};

// --- 后端功能函数 ---

function buildTGMsg(report, isManual, startTime) {
  const listText = report.onlineDetails.map((d, i) => `${i+1}. \`${d.ip}\` | ${d.ms}ms | ${d.loc} | ${d.asn}`).join('\n');
  return `
📊 *ProxyIP 维护报告*
---------------------------
🌐 *监控域名:* \`${report.domain}:${report.port}\`
🕒 *执行时间:* \`${startTime}\`
🎯 *任务类型:* \`${isManual ? '手动更新' : '定时巡检'}\`
---------------------------
✅ *在线节点:* \`${report.onlineDetails.length}\` 个
🔴 *移除失效:* \`${report.removed.length}\` 个
➕ *新增补全:* \`${report.added.length}\` 个
📦 *候选总量:* \`${report.totalCandidate}\` 个

🚀 *当前活跃列表 (IP | 延迟 | 地区 | ASN):*
${listText || '⚠️ 当前无活跃节点'}

${report.removed.length > 0 ? `🗑 *移除列表:* \`${report.removed.join(', ')}\`` : ''}
---------------------------
_Powered by ProxyIP Manager Pro_
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
  const ipv4 = /((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}/g;
  const ipv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})/g;
  return [...new Set([...(text.match(ipv4) || []), ...(text.match(ipv6) || [])])];
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

async function getConfig(env) {
  return await env.PROXYIP_STORE.get('config', { type: 'json' }) || {};
}

async function handleConfig(request, env) {
  if (request.method === 'GET') {
    const config = await getConfig(env);
    const safe = { ...config };
    ['cfApiKey', 'tgBotToken'].forEach(k => { if (safe[k]) safe[k] = "已配置 (不可见)"; });
    return jsonResponse(safe);
  }
  const data = await request.json();
  const old = await getConfig(env);
  if (data.cfApiKey === "已配置 (不可见)") data.cfApiKey = old.cfApiKey;
  if (data.tgBotToken === "已配置 (不可见)") data.tgBotToken = old.tgBotToken;
  await env.PROXYIP_STORE.put('config', JSON.stringify(data));
  return jsonResponse({ success: true });
}

async function handleIPDatabase(request, env) {
  if (request.method === 'GET') return jsonResponse({ data: await env.PROXYIP_STORE.get('ip-database') || '' });
  await env.PROXYIP_STORE.put('ip-database', (await request.json()).data);
  return jsonResponse({ success: true });
}

async function checkProxyIP(proxyip, backends = "") {
  const list = (backends || 'https://check.dwb.pp.ua/check').split(',').map(b => b.trim());
  const backend = list[Math.floor(Math.random() * list.length)];
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
  for (const item of remove || []) if (item.id) await deleteDNSRecord(item.id, config);
  for (const item of add || []) await addDNSRecord(item.ip, config);
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

// --- 前端界面 ---

function getHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ProxyIP/DDNS 监控中心</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .active-tab { border-bottom: 3px solid #3b82f6; color: #3b82f6; }
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-thumb { background: #334155; }
    .scan-pulse { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
  </style>
</head>
<body class="bg-slate-950 text-slate-200 font-sans">
  <div class="max-w-4xl mx-auto p-4 md:p-8">
    <header class="flex flex-wrap justify-between items-center gap-4 mb-8">
      <div>
        <h1 class="text-3xl font-black text-blue-500 tracking-tighter italic">PROXY-DDNS PRO</h1>
        <p class="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Maintenance & Diagnostics System</p>
      </div>
      <button id="main-m-btn" onclick="runMaintenance()" class="bg-blue-600 hover:bg-blue-700 px-6 py-2.5 rounded-2xl text-sm font-bold shadow-xl shadow-blue-900/20 transition-all active:scale-95">一键手动更新</button>
    </header>

    <div class="flex gap-6 border-b border-slate-900 mb-8 text-sm font-bold overflow-x-auto whitespace-nowrap">
      <button onclick="setTab('dashboard')" class="pb-3 tab-btn" id="btn-dashboard">仪表盘</button>
      <button onclick="setTab('database')" class="pb-3 tab-btn" id="btn-database">
        IP 数据源 <span id="scan-badge" class="hidden scan-pulse text-[8px] bg-blue-600 px-1 rounded ml-1 text-white">SCANNING</span>
      </button>
      <button onclick="setTab('tools')" class="pb-3 tab-btn" id="btn-tools">测试诊断</button>
      <button onclick="setTab('config')" class="pb-3 tab-btn" id="btn-config">系统设置</button>
      <button onclick="setTab('logs')" class="pb-3 tab-btn" id="btn-logs">运行日志</button>
    </div>

    <div id="content"></div>
  </div>

  <script>
    let state = { 
      config:{}, currentIPs:[], db:'', logs:[], activeTab:'dashboard', 
      isScanning: false, scanResults: [], scanIndex: 0, scanTotal: 0
    };

    async function api(path, method='GET', body=null) {
      const opts = { method, headers: { 'Content-Type': 'application/json' } };
      if(body) opts.body = JSON.stringify(body);
      const res = await fetch('/api' + path, opts);
      return res.json();
    }

    function setTab(tab) {
      state.activeTab = tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active-tab', b.id === 'btn-' + tab));
      render();
    }

    async function refreshData() {
      state.config = await api('/config');
      state.currentIPs = (await api('/current-ips'))?.ips || [];
      state.db = (await api('/ip-database'))?.data || '';
      state.logs = await api('/logs') || [];
      render();
    }

    async function runMaintenance() {
      const btn = document.getElementById('main-m-btn');
      btn.innerText = '提交中...';
      const res = await api('/maintenance');
      alert('任务已在后台启动，结果将通过 TG 发送。');
      btn.innerText = '一键手动更新';
    }

    async function checkCurrent() {
      render();
      for(let ip of state.currentIPs) {
        ip.st = await api(\`/check?target=\${ip.content}:\${state.config.targetPort}\`);
        render();
      }
    }

    // 持久化扫描逻辑
    async function startScan() {
      if(state.isScanning) return;
      const ips = [...new Set(state.db.split(/[\\n,\\s]+/).filter(i => i && !i.startsWith('#')))];
      state.scanTotal = ips.length;
      state.scanIndex = 0;
      state.scanResults = [];
      state.isScanning = true;
      saveScanState();
      processScan();
    }

    async function processScan() {
      if(!state.isScanning) return;
      const ips = [...new Set(state.db.split(/[\\n,\\s]+/).filter(i => i && !i.startsWith('#')))];
      document.getElementById('scan-badge')?.classList.remove('hidden');

      while(state.scanIndex < ips.length && state.isScanning) {
        // 每组 3 个并发
        const batch = ips.slice(state.scanIndex, state.scanIndex + 3);
        const promises = batch.map(ip => api(\`/check?target=\${ip}:\${state.config.targetPort}\`));
        const results = await Promise.all(promises);
        
        results.forEach((r, i) => {
          if(r?.success) state.scanResults.push({ ip: batch[i], ms: r.responseTime, loc: r.colo });
        });

        state.scanIndex += batch.length;
        saveScanState();
        if(state.activeTab === 'database') renderScanUI();
      }

      if(state.scanIndex >= ips.length) stopScan();
    }

    function stopScan() {
      state.isScanning = false;
      localStorage.removeItem('scan_state');
      document.getElementById('scan-badge')?.classList.add('hidden');
      if(state.activeTab === 'database') render();
    }

    function saveScanState() {
      localStorage.setItem('scan_state', JSON.stringify({
        index: state.scanIndex,
        total: state.scanTotal,
        results: state.scanResults,
        isScanning: state.isScanning
      }));
    }

    function loadScanState() {
      const saved = localStorage.getItem('scan_state');
      if(saved) {
        const parsed = JSON.parse(saved);
        state.scanIndex = parsed.index;
        state.scanTotal = parsed.total;
        state.scanResults = parsed.results;
        state.isScanning = parsed.isScanning;
        if(state.isScanning) {
          document.getElementById('scan-badge')?.classList.remove('hidden');
          processScan();
        }
      }
    }

    function renderScanUI() {
      const resDiv = document.getElementById('scan-res');
      if(!resDiv) return;
      resDiv.innerHTML = \`<div class="flex justify-between text-blue-400 mb-4 border-b border-blue-900 pb-2">
        <span>进度: \${state.scanIndex} / \${state.scanTotal}</span>
        <span>有效: \${state.scanResults.length}</span>
      </div>\`;
      state.scanResults.forEach(r => {
        resDiv.innerHTML += \`<div class="text-[10px] text-slate-500 mb-1 flex justify-between font-mono">
          <span>\${r.ip}</span>
          <span>\${r.loc} | \${r.ms}ms</span>
        </div>\`;
      });
      resDiv.scrollTop = resDiv.scrollHeight;
    }

    async function customTest() {
      const target = document.getElementById('test-target').value;
      const resDiv = document.getElementById('test-res');
      resDiv.innerHTML = "正在测试中...";
      const res = await api(\`/check?target=\${target}\`);
      resDiv.innerHTML = JSON.stringify(res, null, 2);
    }

    async function saveConfig() {
      const body = {};
      ['cfMail','cfDomain','cfZoneId','cfApiKey','targetPort','minActiveIPs','checkBackends','tgBotToken','tgChatId','remoteApis','remoteDomains'].forEach(f => {
        body[f] = document.getElementById('c-'+f).value;
      });
      await api('/config', 'POST', body);
      alert('配置已成功保存并下发');
      refreshData();
    }

    function render() {
      const c = document.getElementById('content');
      if(state.activeTab === 'dashboard') {
        c.innerHTML = \`
          <div class="grid md:grid-cols-2 gap-6 mb-8 text-sm">
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800">
              <h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">监控域名信息</h3>
              <div class="text-2xl font-black text-blue-400 font-mono mb-2">\${state.config.cfDomain || '未配置'}</div>
              <div class="text-xs text-slate-500">端口: \${state.config.targetPort || '-'} | 目标活跃数: \${state.config.minActiveIPs || 0}</div>
            </div>
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 flex justify-between items-center">
              <div>
                <h3 class="text-xs font-bold text-slate-500 uppercase mb-1">在线节点数</h3>
                <div class="text-4xl font-black text-white">\${state.currentIPs.length}</div>
              </div>
              <button onclick="checkCurrent()" class="bg-slate-800 px-4 py-2 rounded-xl text-xs hover:bg-slate-700 transition font-bold">检测状态</button>
            </div>
          </div>
          <div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden">
            <div class="p-6 border-b border-slate-800 font-bold">Cloudflare A 记录列表</div>
            <div class="p-4 space-y-2">
              \${state.currentIPs.map(ip => \`
                <div class="flex justify-between items-center bg-slate-950 p-4 rounded-2xl border border-slate-900">
                  <div>
                    <div class="font-mono text-sm text-slate-200">\${ip.content}</div>
                    <div class="text-[10px] \${ip.st?.success ? 'text-green-500' : 'text-red-400'}">
                      \${ip.st ? (ip.st.success ? '✓ '+ip.st.responseTime+'ms | '+ip.st.colo : '✗ '+ip.st.message) : '等待检测...'}
                    </div>
                  </div>
                  <button onclick="deleteIP('\${ip.id}')" class="text-xs text-slate-600 hover:text-red-400 transition">移除</button>
                </div>
              \`).join('')}
              \${state.currentIPs.length === 0 ? '<p class="p-6 text-slate-600 text-center text-xs">暂无解析记录，请点击一键手动更新</p>' : ''}
            </div>
          </div>\`;
      } else if(state.activeTab === 'database') {
        c.innerHTML = \`
          <div class="grid md:grid-cols-2 gap-6">
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800">
              <h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">本地库管理</h3>
              <textarea id="db-area" class="w-full h-80 bg-slate-950 border border-slate-800 p-4 rounded-2xl font-mono text-[10px] outline-none focus:border-blue-900 transition">\${state.db}</textarea>
              <button onclick="saveDB()" class="w-full mt-4 bg-slate-800 hover:bg-slate-700 py-3 rounded-xl text-sm font-bold transition">保存 IP 库</button>
            </div>
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 flex flex-col">
              <h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">探测结果</h3>
              <div class="flex gap-2 mb-4">
                <button onclick="startScan()" class="flex-1 bg-indigo-600 py-2 rounded-xl text-sm font-bold disabled:opacity-50" \${state.isScanning?'disabled':''}>全库检测</button>
                <button onclick="stopScan()" class="bg-slate-800 px-4 rounded-xl text-xs hover:bg-red-900/50 transition">停止</button>
              </div>
              <div id="scan-res" class="flex-1 bg-black/40 p-4 rounded-2xl font-mono text-[10px] overflow-y-auto min-h-[250px]"></div>
            </div>
          </div>\`;
          if(state.isScanning || state.scanResults.length > 0) renderScanUI();
      } else if(state.activeTab === 'tools') {
        c.innerHTML = \`
          <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 space-y-6">
            <div>
              <h3 class="text-xl font-bold mb-2">后端连通性诊断</h3>
              <p class="text-xs text-slate-500 mb-6 font-mono">实时调用检测接口测试任意 IP 的状态</p>
              <div class="flex gap-3">
                <input id="test-target" class="flex-1 bg-slate-950 border border-slate-800 p-3 rounded-2xl font-mono outline-none" placeholder="例如: 1.1.1.1:50001">
                <button onclick="customTest()" class="bg-blue-600 px-8 py-3 rounded-2xl font-bold transition-all active:scale-95 shadow-lg shadow-blue-900/20">开始诊断</button>
              </div>
            </div>
            <div class="bg-black/50 p-6 rounded-2xl border border-slate-800 shadow-inner">
              <pre id="test-res" class="font-mono text-[11px] text-green-500 overflow-x-auto whitespace-pre-wrap min-h-[150px]">等待输入...</pre>
            </div>
          </div>\`;
      } else if(state.activeTab === 'config') {
        c.innerHTML = \`
          <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 shadow-2xl space-y-6 text-sm">
            <div class="grid md:grid-cols-2 gap-8">
              <div class="space-y-4">
                <h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px]">Cloudflare 配置</h4>
                <div><label class="text-slate-500 block mb-1">邮箱</label><input id="c-cfMail" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfMail||''}"></div>
                <div><label class="text-slate-500 block mb-1">监控域名</label><input id="c-cfDomain" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfDomain||''}"></div>
                <div><label class="text-slate-500 block mb-1">Zone ID</label><input id="c-cfZoneId" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfZoneId||''}"></div>
                <div><label class="text-slate-500 block mb-1">API Token</label><input id="c-cfApiKey" type="password" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfApiKey||''}"></div>
              </div>
              <div class="space-y-4">
                <h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px]">DDNS / 远程采集</h4>
                <div><label class="text-slate-500 block mb-1">API 地址 (逗号分隔)</label><textarea id="c-remoteApis" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl h-20 text-[10px]">\${state.config.remoteApis||''}</textarea></div>
                <div><label class="text-slate-500 block mb-1">克隆域名 (逗号分隔)</label><textarea id="c-remoteDomains" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl h-20 text-[10px]">\${state.config.remoteDomains||''}</textarea></div>
              </div>
              <div class="space-y-4">
                <h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px]">运行参数</h4>
                <div><label class="text-slate-500 block mb-1">检测端口</label><input id="c-targetPort" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.targetPort||'50001'}"></div>
                <div><label class="text-slate-500 block mb-1">最小活跃数</label><input id="c-minActiveIPs" type="number" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.minActiveIPs||3}"></div>
                <div><label class="text-slate-500 block mb-1">TG Token</label><input id="c-tgBotToken" type="password" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.tgBotToken||''}"></div>
                <div><label class="text-slate-500 block mb-1">TG ChatID</label><input id="c-tgChatId" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.tgChatId||''}"></div>
              </div>
              <div class="space-y-4 flex flex-col">
                <h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px]">检测后端列表</h4>
                <textarea id="c-checkBackends" class="w-full flex-1 bg-slate-950 border border-slate-800 p-4 rounded-xl font-mono text-[10px]">\${state.config.checkBackends||''}</textarea>
              </div>
            </div>
            <button onclick="saveConfig()" class="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-2xl font-black transition-all active:scale-[0.99] shadow-xl shadow-blue-900/10">保存并应用配置</button>
          </div>\`;
      } else if(state.activeTab === 'logs') {
        c.innerHTML = \`
          <div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden shadow-2xl">
            <div class="p-4 border-b border-slate-800 flex justify-between items-center px-8">
              <span class="font-bold">System Events</span>
              <button onclick="api('/logs','DELETE').then(refreshData)" class="text-xs text-red-500">清除日志</button>
            </div>
            <div class="h-[500px] overflow-y-auto p-4 font-mono text-[10px] space-y-1 text-slate-400">
              \${state.logs.map(l => \`<div><span class="text-slate-600">[\${l.t}]</span> <span class="\${l.y==='ERROR'?'text-red-500':l.y==='TASK'?'text-blue-500':'text-slate-500'}">[\${l.y}]</span> \${l.m}</div>\`).join('')}
              \${state.logs.length === 0 ? '<p class="text-center text-slate-700 mt-20 italic">No events recorded.</p>' : ''}
            </div>
          </div>\`;
      }
    }

    async function deleteIP(id) {
      if(confirm('确定移除该解析记录？')) { await api('/update-dns', 'POST', { remove:[{id}] }); refreshData(); }
    }

    async function saveDB() {
      await api('/ip-database', 'POST', { data: document.getElementById('db-area').value });
      alert('本地库已同步');
    }

    window.onload = async () => { 
      await refreshData(); 
      loadScanState(); // 恢复扫描进度
      setInterval(refreshData, 30000); 
    };
  </script>
</body>
</html>`;
}
