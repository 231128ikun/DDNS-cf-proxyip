// ProxyIP 监控管理系统 - 终极融合增强版
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
        return jsonResponse({ success: true, message: '一键同步/维护任务已在后台启动' });
      }
    } catch (e) {
      return jsonResponse({ error: e.message }, 500);
    }
    return new Response('Not Found', { status: 404 });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(this.runMaintenance(env, false));
  },

  // 核心维护逻辑
  async runMaintenance(env, isManual = false) {
    const config = await getConfig(env);
    if (!config.cfApiKey) return;

    const startTime = new Date().toLocaleString('zh-CN');
    await addLog(env, `[${isManual ? '手动' : '定时'}] 启动全量同步...`, "TASK");
    
    let report = {
      domain: config.cfDomain,
      removed: [],
      added: [],
      active: 0,
      totalCandidate: 0
    };

    try {
      // 1. 采集候选 IP
      let pool = [];
      // 本地库
      const localDB = await env.PROXYIP_STORE.get('ip-database') || '';
      pool.push(...extractIPs(localDB));
      // 远程 API
      if (config.remoteApis) {
        for (const api of config.remoteApis.split(',')) {
          try {
            const res = await fetch(api.trim(), { signal: AbortSignal.timeout(5000) });
            pool.push(...extractIPs(await res.text()));
          } catch (e) {}
        }
      }
      // 远程域名
      if (config.remoteDomains) {
        for (const dom of config.remoteDomains.split(',')) {
          pool.push(...(await resolveDomain(dom.trim())));
        }
      }
      pool = [...new Set(pool)]; // 去重
      report.totalCandidate = pool.length;

      // 2. 检查现有解析
      const currentRecords = await fetchDNSRecords(config);
      const healthyIPs = [];
      
      for (const record of currentRecords) {
        const res = await checkProxyIP(`${record.content}:${config.targetPort}`, config.checkBackends);
        if (res.success) {
          healthyIPs.push(record.content);
        } else {
          await deleteDNSRecord(record.id, config);
          report.removed.push(record.content);
        }
        await sleep(300);
      }

      // 3. 补齐不足的部分
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
            healthyIPs.push(ip);
            count++;
          }
          await sleep(300);
        }
      }

      report.active = healthyIPs.length;
      await addLog(env, `同步结束: 移除${report.removed.length}，新增${report.added.length}`, "TASK");
      
      // 发送 TG 通知
      await sendTGNotification(buildTGMsg(report, isManual, startTime), config);

    } catch (e) {
      await addLog(env, `维护异常: ${e.message}`, "ERROR");
    }
  }
};

// --- 后端功能函数 ---

function buildTGMsg(report, isManual, startTime) {
  const status = report.active >= 1 ? "✅ 运行正常" : "⚠️ 节点不足";
  return `
📊 *ProxyIP 维护摘要*
---------------------------
🌐 *监控域名:* \`${report.domain}\`
🕒 *执行时间:* \`${startTime}\`
🎯 *任务类型:* \`${isManual ? '手动强制维护' : '系统定时巡检'}\`
---------------------------
${status}
🟢 *当前在线:* \`${report.active}\` 个
🔴 *失效移除:* \`${report.removed.length}\` 个
➕ *新增补全:* \`${report.added.length}\` 个
📦 *库内候选:* \`${report.totalCandidate}\` 个

${report.removed.length > 0 ? `🗑 *移除列表:* \n\`${report.removed.join(', ')}\`\n` : ''}
${report.added.length > 0 ? `🚀 *新增列表:* \n\`${report.added.join(', ')}\`\n` : ''}
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
  return [...(text.match(ipv4) || []), ...(text.match(ipv6) || [])];
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
  </style>
</head>
<body class="bg-slate-950 text-slate-200 font-sans">
  <div class="max-w-4xl mx-auto p-4 md:p-8">
    <header class="flex flex-wrap justify-between items-center gap-4 mb-8">
      <div>
        <h1 class="text-3xl font-black text-blue-500 tracking-tighter italic">PROXY-DDNS PRO</h1>
        <p class="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Maintenance & Diagnostics System</p>
      </div>
      <button onclick="runMaintenance()" class="bg-blue-600 hover:bg-blue-700 px-6 py-2.5 rounded-2xl text-sm font-bold shadow-xl shadow-blue-900/20 transition-all active:scale-95">一键全量维护</button>
    </header>

    <div class="flex gap-6 border-b border-slate-900 mb-8 text-sm font-bold overflow-x-auto whitespace-nowrap">
      <button onclick="setTab('dashboard')" class="pb-3 tab-btn" id="btn-dashboard">仪表盘</button>
      <button onclick="setTab('database')" class="pb-3 tab-btn" id="btn-database">IP 数据源</button>
      <button onclick="setTab('tools')" class="pb-3 tab-btn" id="btn-tools">测试诊断</button>
      <button onclick="setTab('config')" class="pb-3 tab-btn" id="btn-config">系统配置</button>
      <button onclick="setTab('logs')" class="pb-3 tab-btn" id="btn-logs">运行日志</button>
    </div>

    <div id="content"></div>
  </div>

  <script>
    let state = { config:{}, currentIPs:[], db:'', logs:[], activeTab:'dashboard', stopScan: false, loading: false };

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
      await api('/maintenance');
      alert('同步任务已提交至后台，结果将通过 TG 发送。');
      setTimeout(refreshData, 2000);
    }

    async function checkCurrent() {
      state.loading = true; render();
      for(let ip of state.currentIPs) {
        ip.st = await api(\`/check?target=\${ip.content}:\${state.config.targetPort}\`);
        render();
      }
      state.loading = false; render();
    }

    async function customTest() {
      const target = document.getElementById('test-target').value;
      const resDiv = document.getElementById('test-res');
      resDiv.innerHTML = "正在向后端发起请求...";
      const res = await api(\`/check?target=\${target}\`);
      resDiv.innerHTML = JSON.stringify(res, null, 2);
    }

    async function startScan() {
      state.stopScan = false;
      const resDiv = document.getElementById('scan-res');
      resDiv.innerHTML = '<p class="text-blue-500">开始探测备选库...</p>';
      const ips = [...new Set(state.db.split(/[\\n,\\s]+/).filter(i => i && !i.startsWith('#')))];
      let valid = [];
      for(let ip of ips) {
        if(state.stopScan) break;
        const r = await api(\`/check?target=\${ip}:\${state.config.targetPort}\`);
        if(r?.success) {
          valid.push(ip);
          resDiv.innerHTML += \`<div class="text-[10px] text-slate-500">\${ip} - OK (\${r.responseTime}ms)</div>\`;
          resDiv.scrollTop = resDiv.scrollHeight;
        }
      }
      resDiv.innerHTML += \`<div class="mt-2 p-2 bg-blue-900/20 text-xs rounded text-blue-300">探测结束，共发现 \${valid.length} 个有效节点。</div>\`;
    }

    async function saveConfig() {
      const fields = ['cfMail','cfDomain','cfZoneId','cfApiKey','targetPort','minActiveIPs','checkBackends','tgBotToken','tgChatId','remoteApis','remoteDomains'];
      const body = {};
      fields.forEach(f => body[f] = document.getElementById('c-'+f).value);
      await api('/config', 'POST', body);
      alert('设置已成功应用');
      refreshData();
    }

    async function saveDB() {
      await api('/ip-database', 'POST', { data: document.getElementById('db-area').value });
      alert('本地数据已同步');
    }

    function render() {
      const c = document.getElementById('content');
      if(state.activeTab === 'dashboard') {
        c.innerHTML = \`
          <div class="grid md:grid-cols-2 gap-6 mb-8">
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800">
              <h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">监控域名信息</h3>
              <div class="text-2xl font-black text-blue-400 font-mono mb-2">\${state.config.cfDomain || '未配置'}</div>
              <div class="text-xs text-slate-500">目标活跃数: \${state.config.minActiveIPs || 0} | 端口: \${state.config.targetPort || '-'}</div>
            </div>
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 flex justify-between items-center">
              <div>
                <h3 class="text-xs font-bold text-slate-500 uppercase mb-1">在线节点</h3>
                <div class="text-4xl font-black text-white">\${state.currentIPs.length}</div>
              </div>
              <button onclick="checkCurrent()" class="bg-slate-800 px-4 py-2 rounded-xl text-xs">\${state.loading ? '正在检测...' : '手动刷新状态'}</button>
            </div>
          </div>
          <div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden">
            <div class="p-6 border-b border-slate-800 font-bold">当前解析明细 (A记录)</div>
            <div class="p-4 space-y-2">
              \${state.currentIPs.map(ip => \`
                <div class="flex justify-between items-center bg-slate-950 p-4 rounded-2xl border border-slate-900">
                  <div>
                    <div class="font-mono text-sm text-slate-200">\${ip.content}</div>
                    <div class="text-[10px] \${ip.st?.success ? 'text-green-500' : 'text-red-500'}">
                      \${ip.st ? (ip.st.success ? '✓ '+ip.st.responseTime+'ms | '+ip.st.colo : '✗ '+ip.st.message) : '等待检测...'}
                    </div>
                  </div>
                  <button onclick="deleteIP('\${ip.id}')" class="text-xs text-slate-600 hover:text-red-500">移除</button>
                </div>
              \`).join('')}
              \${state.currentIPs.length === 0 ? '<p class="p-4 text-slate-600 text-center">暂无记录，请点击一键维护</p>' : ''}
            </div>
          </div>\`;
      } else if(state.activeTab === 'database') {
        c.innerHTML = \`
          <div class="grid md:grid-cols-2 gap-6">
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800">
              <h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">本地备选库</h3>
              <textarea id="db-area" class="w-full h-80 bg-slate-950 border border-slate-800 p-4 rounded-2xl font-mono text-[10px] outline-none">\${state.db}</textarea>
              <button onclick="saveDB()" class="w-full mt-4 bg-slate-800 py-3 rounded-xl text-sm font-bold">保存并同步</button>
            </div>
            <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 flex flex-col">
              <h3 class="text-xs font-bold text-slate-500 uppercase mb-4 tracking-tighter">全库实时探测</h3>
              <div class="flex gap-2 mb-4">
                <button onclick="startScan()" class="flex-1 bg-indigo-600 py-2 rounded-xl text-sm font-bold">全量扫描</button>
                <button onclick="state.stopScan=true" class="bg-slate-800 px-4 rounded-xl text-xs">停止</button>
              </div>
              <div id="scan-res" class="flex-1 bg-black/40 p-4 rounded-2xl font-mono text-[10px] overflow-y-auto min-h-[250px]"></div>
            </div>
          </div>\`;
      } else if(state.activeTab === 'tools') {
        c.innerHTML = \`
          <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 space-y-6">
            <div>
              <h3 class="text-xl font-bold mb-2">后端接口诊断</h3>
              <p class="text-xs text-slate-500 mb-6 font-mono">通过随机轮询配置的后端，测试目标 IP 及其端口的连通性。</p>
              <div class="flex gap-3">
                <input id="test-target" class="flex-1 bg-slate-950 border border-slate-800 p-3 rounded-2xl font-mono" placeholder="例如: 1.1.1.1:50001">
                <button onclick="customTest()" class="bg-blue-600 px-8 py-3 rounded-2xl font-bold transition-all active:scale-95">测试</button>
              </div>
            </div>
            <div class="bg-black/50 p-6 rounded-2xl border border-slate-800 shadow-inner">
              <h4 class="text-xs font-bold text-slate-600 mb-2 uppercase">Response Header & Body</h4>
              <pre id="test-res" class="font-mono text-[11px] text-green-500 overflow-x-auto whitespace-pre-wrap min-h-[150px]"></pre>
            </div>
          </div>\`;
      } else if(state.activeTab === 'config') {
        c.innerHTML = \`
          <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 shadow-2xl space-y-6 text-sm">
            <div class="grid md:grid-cols-2 gap-8">
              <div class="space-y-4">
                <h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px]">Cloudflare 核心配置</h4>
                <div><label class="text-slate-500 block mb-1">CF 邮箱</label><input id="c-cfMail" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfMail||''}"></div>
                <div><label class="text-slate-500 block mb-1">监控域名</label><input id="c-cfDomain" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfDomain||''}"></div>
                <div><label class="text-slate-500 block mb-1">Zone ID</label><input id="c-cfZoneId" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfZoneId||''}"></div>
                <div><label class="text-slate-500 block mb-1">API Token</label><input id="c-cfApiKey" type="password" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl" value="\${state.config.cfApiKey||''}"></div>
              </div>
              <div class="space-y-4">
                <h4 class="text-blue-500 font-bold uppercase tracking-widest text-[10px]">远程同步 (DDNS 模式)</h4>
                <div><label class="text-slate-500 block mb-1">远程 API 地址 (逗号分隔)</label><textarea id="c-remoteApis" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl h-20 text-[10px]">\${state.config.remoteApis||''}</textarea></div>
                <div><label class="text-slate-500 block mb-1">待克隆解析域名 (逗号分隔)</label><textarea id="c-remoteDomains" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded-xl h-20 text-[10px]">\${state.config.remoteDomains||''}</textarea></div>
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
            <button onclick="saveConfig()" class="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-2xl font-black text-white shadow-xl shadow-blue-900/10 transition-all active:scale-[0.99]">保存并部署配置</button>
          </div>\`;
      } else if(state.activeTab === 'logs') {
        c.innerHTML = \`
          <div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden shadow-2xl">
            <div class="p-4 border-b border-slate-800 flex justify-between items-center px-8">
              <span class="font-bold">System Events</span>
              <button onclick="api('/logs','DELETE').then(refreshData)" class="text-xs text-red-500">清空记录</button>
            </div>
            <div class="h-[500px] overflow-y-auto p-4 font-mono text-[10px] space-y-1">
              \${state.logs.map(l => \`<div><span class="text-slate-600">[\${l.t}]</span> <span class="\${l.y==='ERROR'?'text-red-500':l.y==='TASK'?'text-blue-500':'text-slate-400'}">[\${l.y}]</span> \${l.m}</div>\`).join('')}
              \${state.logs.length === 0 ? '<p class="text-center text-slate-700 mt-20">No data logs recorded.</p>' : ''}
            </div>
          </div>\`;
      }
    }

    async function deleteIP(id) {
      if(confirm('确定移除？')) { await api('/update-dns', 'POST', { remove:[{id}] }); refreshData(); }
    }

    window.onload = () => { setTab('dashboard'); refreshData(); setInterval(refreshData, 30000); };
  </script>
</body>
</html>`;
}
