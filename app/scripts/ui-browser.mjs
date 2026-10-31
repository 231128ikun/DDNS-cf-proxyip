import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';

export class Cdp {
  constructor(url) {
    this.url = url;
    this.id = 0;
    this.pending = new Map();
    this.listeners = new Map();
  }

  async connect() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error', reject, { once: true });
    });
    this.ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== undefined) {
        const entry = this.pending.get(message.id);
        if (!entry) return;
        this.pending.delete(message.id);
        clearTimeout(entry.timer);
        if (message.error) entry.reject(new Error(JSON.stringify(message.error)));
        else entry.resolve(message.result);
      } else {
        for (const fn of this.listeners.get(`${message.sessionId || ''}:${message.method}`) || []) fn(message.params);
      }
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }, 15_000);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  wait(sessionId, method, timeout = 15_000) {
    return new Promise((resolve, reject) => {
      const key = `${sessionId || ''}:${method}`;
      const remove = () => this.listeners.set(key, (this.listeners.get(key) || []).filter((item) => item !== fn));
      const timer = setTimeout(() => { remove(); reject(new Error(`timeout waiting ${method}`)); }, timeout);
      const fn = (params) => { clearTimeout(timer); remove(); resolve(params); };
      this.listeners.set(key, [...(this.listeners.get(key) || []), fn]);
    });
  }

  async evaluate(sessionId, expression) {
    const result = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result?.value;
  }

  async until(sessionId, expression) {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (await this.evaluate(sessionId, expression)) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`UI condition timed out: ${expression}`);
  }

  async click(sessionId, selector) {
    const point = await this.evaluate(sessionId, `(async () => {
      const element = document.querySelector(${JSON.stringify(selector)});
      if (!element) throw new Error('Missing control: ' + ${JSON.stringify(selector)});
      element.scrollIntoView({ block: 'center', behavior: 'instant' });
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const box = element.getBoundingClientRect();
      const point = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
      const hit = document.elementFromPoint(point.x, point.y);
      if (!box.width || !box.height || !hit || !element.contains(hit)) throw new Error('Control is hidden or covered: ' + ${JSON.stringify(selector)});
      if (element.disabled) throw new Error('Control is disabled: ' + ${JSON.stringify(selector)});
      return point;
    })()`);
    await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', button: 'left', clickCount: 1, ...point }, sessionId);
    await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', button: 'left', clickCount: 1, ...point }, sessionId);
  }

  close() {
    this.ws.close();
    for (const entry of this.pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('CDP closed')); }
    this.pending.clear();
  }
}

export async function launchBrowser(chrome) {
  const executable = [chrome, process.env.CHROME_PATH,
    `${process.env.ProgramFiles}/Google/Chrome/Application/chrome.exe`,
    `${process.env['ProgramFiles(x86)']}/Microsoft/Edge/Application/msedge.exe`,
    `${process.env.LOCALAPPDATA}/Google/Chrome/Application/chrome.exe`,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium',
  ].find((item) => item && existsSync(item));
  if (!executable) throw new Error('未找到 Chrome/Edge；请设置 CHROME_PATH');
  const profile = mkdtempSync(join(tmpdir(), 'ddns-ui-browser-'));
  const child = spawn(executable, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-gpu', '--hide-scrollbars',
    '--disable-background-timer-throttling', '--disable-renderer-backgrounding', '--disable-backgrounding-occluded-windows',
    '--force-device-scale-factor=1', ...(process.env.CI ? ['--no-sandbox'] : []), 'about:blank'], { stdio: 'ignore' });
  let cdp;
  const close = async () => {
    await cdp?.send('Browser.close').catch(() => {});
    cdp?.close();
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        if (process.platform !== 'win32') { child.once('exit', resolve); child.kill(); return; }
        const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
        killer.on('exit', resolve);
        killer.on('error', resolve);
      });
    }
    if (!resolve(profile).startsWith(resolve(tmpdir()) + sep)) throw new Error('Browser profile escaped temp directory');
    await new Promise((resolve) => setTimeout(resolve, 200));
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
    catch { console.error(`Chrome 临时目录未能清理：${profile}`); }
  };
  try {
    const activePort = join(profile, 'DevToolsActivePort');
    const deadline = Date.now() + 20_000;
    while (!existsSync(activePort)) {
      if (child.exitCode !== null || Date.now() > deadline) throw new Error('Chrome 调试端口未就绪');
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const [port, socket] = readFileSync(activePort, 'utf8').trim().split('\n');
    cdp = new Cdp(`ws://127.0.0.1:${port}${socket}`);
    await cdp.connect();
    return { cdp, close };
  } catch (error) {
    await close();
    throw error;
  }
}
