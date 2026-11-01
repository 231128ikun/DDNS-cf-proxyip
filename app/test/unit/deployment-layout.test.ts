import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { APP_VERSION } from '../../src/worker';

const appRoot = new URL('../../', import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, appRoot), 'utf8');

/** 一键部署将 app 复制为仓库根目录，部署配置不得依赖父目录。 */
describe('standalone application layout', () => {
  it('resolves Worker source and static assets from the application root', () => {
    const config = read('wrangler.toml');
    const entry = /^main\s*=\s*"([^"]+)"/m.exec(config)?.[1];
    const assets = /^directory\s*=\s*"([^"]+)"/m.exec(config)?.[1];
    expect(entry).toBe('src/index.ts');
    expect(assets).toBe('dist/web');
    expect(existsSync(new URL(entry!, appRoot))).toBe(true);
    expect(config).toContain('binding = "IP_DATA"');
    expect(config).toContain('run_worker_first = ["/api/*"]');
  });

  it('runs complete checks before deployment with the local Wrangler config', () => {
    const { scripts } = JSON.parse(read('package.json'));
    expect(scripts.deploy).toBe('npm run check && wrangler deploy');
    expect(scripts.build).toBe('npm run clean && npm run build:worker');
    expect(scripts.check).toBe('npm run typecheck && npm run test:contract && npm run test:unit && npm run build && npm run check:size && npm run smoke');
    expect(JSON.stringify(scripts)).not.toContain('../wrangler.toml');
  });

  it('uses the date version without a second npm release identifier', () => {
    const manifest = JSON.parse(read('package.json'));
    const lock = JSON.parse(read('package-lock.json'));
    expect(APP_VERSION).toMatch(/^\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}$/);
    expect(manifest.private).toBe(true);
    expect(manifest.version).toBeUndefined();
    expect(lock.version).toBeUndefined();
    expect(lock.packages[''].version).toBeUndefined();
  });

  it('includes license notices and an empty secret declaration for deployment', () => {
    expect(read('LICENSE')).toContain('MIT License');
    expect(read('LICENSE')).toContain('Copyright (c) 2025 DDNS-cf-proxyip Contributors');
    expect(read('.dev.vars.example').trim()).toBe('AUTH_KEY=');
  });
});
