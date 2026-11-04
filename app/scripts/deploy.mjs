import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

const appRoot = fileURLToPath(new URL('../', import.meta.url));
const resourceId = /^[a-f0-9]{32}$/i;
const secretName = /token|secret|password|auth[_-]?key|cf[_-]?key|api[_-]?key|tg[_-]?id/i;
const stripAnsi = value => value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const runWrangler = createWranglerRunner();

export function parseKvConflict(output) {
  const text = stripAnsi(output);
  if (!/\[code:\s*10014\]/i.test(text)) return null;
  const accounts = [...text.matchAll(/\/accounts\/([a-f0-9]{32})\/storage\/kv\/namespaces(?=[)\s]|$)/gi)];
  if (accounts.length === 0) return null;
  let binding;
  let title;
  for (const line of text.split(/\r?\n/)) {
    if (line.includes('[custom build]')) continue;
    const provisioning = /^\s*Provisioning\s+(\S+)\s+\(KV Namespace\)/.exec(line);
    if (/^\s*Provisioning\s+/.test(line)) {
      binding = provisioning?.[1];
      title = undefined;
    }
    if (binding === 'IP_DATA') {
      const creation = /Creating new KV Namespace "([A-Za-z0-9._-]+)"/.exec(line);
      if (creation) title = creation[1];
    }
  }
  return binding === 'IP_DATA' && title ? { accountId: accounts.at(-1)[1], title } : null;
}

export function materializeConfig(rawConfig, sourceDir) {
  if (!isRecord(rawConfig)) throw new Error('Wrangler 配置必须为对象');
  const config = structuredClone(rawConfig);
  const absolute = value => isAbsolute(value) ? value : resolve(sourceDir, value);
  for (const section of [config, ...Object.values(config.env ?? {})]) {
    if (!isRecord(section)) throw new Error('Wrangler 环境配置必须为对象');
    for (const key of ['main', 'tsconfig', 'base_dir']) {
      if (typeof section[key] === 'string') section[key] = absolute(section[key]);
    }
    if (isRecord(section.alias)) {
      for (const [name, value] of Object.entries(section.alias)) {
        if (typeof value === 'string' && /^\.\.?[/\\]/.test(value)) section.alias[name] = absolute(value);
      }
    }
    if (typeof section.assets?.directory === 'string') section.assets.directory = absolute(section.assets.directory);
    if (isRecord(section.build)) {
      section.build.cwd = typeof section.build.cwd === 'string' ? absolute(section.build.cwd) : sourceDir;
      if (typeof section.build.watch_dir === 'string') section.build.watch_dir = absolute(section.build.watch_dir);
      else if (Array.isArray(section.build.watch_dir)) section.build.watch_dir = section.build.watch_dir.map(absolute);
    }
  }
  return config;
}

export function sanitizeLog(text, secrets = []) {
  let result = stripAnsi(text);
  for (const value of [...new Set(secrets)].filter(value => typeof value === 'string' && value.length > 0).sort((a, b) => b.length - a.length)) {
    for (const form of new Set([value, JSON.stringify(value).slice(1, -1)])) result = result.split(form).join('[redacted]');
  }
  return result.replace(/\b[a-f0-9]{32}\b/gi, '[resource-id]');
}

export async function deployWithKvRecovery(rawConfig, { args = [], sourceDir = appRoot, run = runWrangler, log = console.log, env = process.env } = {}) {
  const { environment, authArgs, forwardedArgs, dryRun, envFiles } = deploymentOptions(args, sourceDir);
  const config = materializeConfig(rawConfig, sourceDir);
  const section = environment ? config.env?.[environment] : config;
  if (!isRecord(section)) throw new Error('部署环境不存在');
  const bindings = (section.kv_namespaces ?? []).filter(binding => binding.binding === 'IP_DATA');
  if (bindings.length !== 1) throw new Error('目标部署环境必须配置一个 IP_DATA KV 绑定');
  const binding = bindings[0];
  const secrets = secretValues(env, rawConfig, args, envFiles);
  const print = text => { if (text.trim()) log(sanitizeLog(text, secrets)); };
  const parent = join(sourceDir, '.wrangler', 'tmp');
  mkdirSync(parent, { recursive: true });
  const directory = mkdtempSync(join(parent, 'deploy-'));
  const configPath = join(directory, 'wrangler.json');
  const writeConfig = () => writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  const deployArgs = ['deploy', ...forwardedArgs, '--config', configPath, '--autoconfig=false'];

  try {
    writeConfig();
    const first = await run(deployArgs);
    if (first.exitCode === 0 && !first.interrupted) { print(first.stdout + first.stderr); return 0; }
    const conflict = dryRun || binding.id || first.interrupted ? null : parseKvConflict(first.stdout + first.stderr);
    if (!conflict) { print(first.stdout + first.stderr); return first.exitCode || 1; }

    const configuredAccount = section.account_id ?? config.account_id;
    if (configuredAccount && configuredAccount !== conflict.accountId) {
      print(first.stdout + first.stderr);
      log('KV 冲突账号与部署配置不一致，未更换绑定。');
      return 1;
    }
    section.account_id = conflict.accountId;
    writeConfig();
    print(first.stdout);
    log('IP_DATA 创建遇到同名冲突，查找该账号下的同名 KV。');
    const listed = await run(['kv', 'namespace', 'list', '--config', configPath, ...authArgs]);
    if (listed.exitCode !== 0 || listed.interrupted) {
      print(listed.stderr);
      log('无法读取 KV 命名空间清单，未重试发布。');
      return listed.exitCode || 1;
    }
    let namespaces;
    try { namespaces = JSON.parse(stripAnsi(listed.stdout).trim()); }
    catch { log('KV 命名空间清单不是有效 JSON，未重试发布。'); return 1; }
    if (!Array.isArray(namespaces)) { log('KV 命名空间清单格式无效，未重试发布。'); return 1; }
    const matching = namespaces.filter(item => isRecord(item) && item.title === conflict.title);
    if (matching.length !== 1 || typeof matching[0].id !== 'string' || !resourceId.test(matching[0].id)) {
      log('未找到唯一、有效的同名 KV，未更换绑定或重试发布。');
      return 1;
    }
    binding.id = matching[0].id;
    writeConfig();
    log('已选择同名 KV，使用临时绑定配置重试一次发布。');
    const retry = await run(deployArgs);
    print(retry.stdout + retry.stderr);
    return retry.exitCode === 0 && !retry.interrupted ? 0 : retry.exitCode || 1;
  } finally {
    try { rmSync(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); }
    catch { log('临时部署目录未能清理，请检查本地 .wrangler/tmp 的文件权限。'); }
  }
}

function deploymentOptions(args, sourceDir) {
  let environment;
  let dryRun = false;
  const authArgs = [];
  const forwardedArgs = [];
  const envFiles = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    const key = argument.split('=')[0];
    if (['--config', '-c', '--cwd'].includes(key)) throw new Error('部署入口使用应用目录的 wrangler.toml；仓库根目录请使用 npm --prefix app run deploy');
    if (key === '--autoconfig') {
      const value = argument.includes('=') ? argument.slice(argument.indexOf('=') + 1) : args[index + 1] === 'false' ? args[++index] : 'true';
      if (value !== 'false') throw new Error('项目使用唯一 Wrangler 配置，不启用自动生成配置');
      continue;
    }
    if (key === '--dry-run') {
      const value = argument.includes('=') ? argument.slice(argument.indexOf('=') + 1) : args[index + 1] === 'false' ? args[++index] : 'true';
      if (!['true', 'false'].includes(value)) throw new Error('--dry-run 必须是 true 或 false');
      dryRun = value === 'true';
      forwardedArgs.push(`--dry-run=${value}`);
      continue;
    }
    if (['--env', '-e', '--profile', '--env-file'].includes(key)) {
      const value = argument.includes('=') ? argument.slice(argument.indexOf('=') + 1) : args[++index];
      if (!value || value.startsWith('-')) throw new Error(`${key} 缺少有效值`);
      if (key === '--env' || key === '-e') environment = value;
      const resolvedValue = key === '--env-file' ? resolve(sourceDir, value) : value;
      if (key === '--env-file') envFiles.push(resolvedValue);
      authArgs.push(key, resolvedValue);
      forwardedArgs.push(key, resolvedValue);
    } else forwardedArgs.push(argument);
  }
  if (envFiles.length === 0) {
    for (const path of ['.env', ...(environment ? [`.env.${environment}`] : [])]) {
      const file = join(sourceDir, path);
      if (existsSync(file)) {
        envFiles.push(file);
        authArgs.push('--env-file', file);
        forwardedArgs.push('--env-file', file);
      }
    }
  }
  return { environment, authArgs, forwardedArgs, dryRun, envFiles };
}

function secretValues(env, config, args, envFiles) {
  const values = Object.entries(env).filter(([key]) => secretName.test(key)).map(([, value]) => value);
  for (const file of envFiles) {
    const parsed = parseEnv(readFileSync(file, 'utf8'));
    values.push(...Object.entries(parsed).filter(([key]) => secretName.test(key)).map(([, value]) => value));
  }
  for (const section of [config, ...Object.values(config.env ?? {})]) {
    values.push(...Object.entries(section.vars ?? {}).filter(([key]) => secretName.test(key)).map(([, value]) => value));
  }
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--var' || args[index].startsWith('--var=')) {
      const value = args[index].startsWith('--var=') ? args[index].slice('--var='.length) : args[index + 1] ?? '';
      const colon = value.indexOf(':');
      if (colon > 0 && secretName.test(value.slice(0, colon))) values.push(value.slice(colon + 1));
    }
  }
  return values;
}

export function createWranglerRunner({ cwd = appRoot, script = join(appRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js'), env = process.env, timeoutMs = 180_000 } = {}) {
  return args => new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd, env: { ...env, WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG: 'log' }, stdio: ['inherit', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let exceeded = false;
    let timedOut = false;
    const collect = key => chunk => {
      if (key === 'stdout') stdout += chunk.toString(); else stderr += chunk.toString();
      if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 8 * 1024 * 1024) { exceeded = true; child.kill(); }
    };
    child.stdout.on('data', collect('stdout'));
    child.stderr.on('data', collect('stderr'));
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => {
      clearTimeout(timer);
      resolveResult({ exitCode: exceeded || timedOut || code === null ? 1 : code, stdout, stderr, interrupted: exceeded || timedOut || code === null });
    });
  });
}

async function main() {
  const { experimental_readRawConfig } = await import('wrangler');
  const source = join(appRoot, 'wrangler.toml');
  const { rawConfig } = experimental_readRawConfig({ config: source }, { useRedirectIfAvailable: false });
  process.exitCode = await deployWithKvRecovery(rawConfig, { args: process.argv.slice(2), sourceDir: dirname(source) });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('部署准备或命令执行失败，请检查 Wrangler 配置和本地权限。'); process.exitCode = 1; });
}
