import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const readSource = (path: string): string => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');

const cssRule = (styles: string, selector: string): string => {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = styles.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`));
  if (!match?.[1]) throw new Error(`missing CSS rule: ${selector}`);
  return match[1];
};

describe('dashboard visual alignment', () => {
  it('keeps the compact palette and renders controls at accessible sizes', () => {
    const styles = readSource('web/src/styles.css');
    const guide = cssRule(styles, '.guide-toggle');
    const smallButton = cssRule(styles, '.btn-sm');

    expect(styles).toContain('--color-primary: #007aff;');
    expect(styles).toContain('--color-page: #f5f5f7;');
    expect(styles).toContain('--color-console-bg: #1c1c1e;');
    expect(styles).toContain('--content-max: 1140px;');
    expect(guide).toContain('min-height: 36px;');
    expect(guide).toContain('background: var(--color-surface);');
    expect(smallButton).toContain('min-height: 34px;');
  });

  it('uses semantic console colors instead of one hard-coded green', () => {
    const styles = readSource('web/src/styles.css');
    const consoleRule = cssRule(styles, '.console');

    expect(consoleRule).toContain('background: var(--color-console-bg);');
    expect(consoleRule).toContain('color: var(--color-console-text);');
    expect(consoleRule).not.toMatch(/#[0-9a-f]{3,8}/i);
    expect(styles).toContain('.console-event-success');
    expect(styles).toContain('.console-event-warning');
    expect(styles).toContain('.console-event-error');
  });

  it('aligns the desktop workspace cards and keeps bindings full width below them', () => {
    const styles = readSource('web/src/styles.css');
    const dashboard = readSource('web/src/components/dashboard-page.tsx');
    const consoleColumn = dashboard.indexOf('class="col-lg-5"');
    const bindings = dashboard.indexOf('<DomainBindingsCard');

    expect(styles).toContain('align-items: stretch;');
    expect(styles).toContain('min-height: 580px;');
    expect(consoleColumn).toBeGreaterThan(-1);
    expect(bindings).toBeGreaterThan(consoleColumn);
    expect(dashboard).toContain('<div class="col-12">');
  });

  it('uses the compact main-aligned card system across dashboard and configuration', () => {
    const styles = readSource('web/src/styles.css');
    const hero = cssRule(styles, '.hero');
    const card = cssRule(styles, '.card');
    const grid = cssRule(styles, '.config-card-grid');
    const miniCard = cssRule(styles, '.config-mini-card');
    const emptyState = cssRule(styles, '.config-empty-state');

    expect(hero).not.toContain('grid-template-columns');
    expect(card).toContain('border: 0;');
    expect(card).toContain('border-radius: 20px;');
    expect(grid).toContain('grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));');
    expect(grid).toContain('gap: var(--space-5);');
    expect(miniCard).toContain('background: var(--color-surface-subtle);');
    expect(miniCard).toContain('padding: var(--space-6);');
    expect(miniCard).toContain('min-height: 120px;');
    expect(miniCard).toContain('border-radius: var(--radius-card-sm);');
    expect(emptyState).toContain('grid-column: 1 / -1;');
    expect(emptyState).toContain('min-height: 120px;');
  });

  it('keeps the hero hierarchy and form rhythm aligned with main', () => {
    const styles = readSource('web/src/styles.css');
    const heroMarkup = readSource('web/src/components/hero.tsx');
    const hero = cssRule(styles, '.hero');
    const heroTitle = cssRule(styles, '.hero h1');
    const targetSummary = cssRule(styles, '.target-summary');
    const configGrid = cssRule(styles, '.config-grid');

    expect(heroMarkup).not.toContain('hero-eyebrow');
    expect(hero).not.toContain('grid-template-columns');
    expect(heroTitle).toContain('color: var(--color-text-muted);');
    expect(heroTitle).toContain('font-weight: 600;');
    expect(targetSummary).toContain('min-height: 76px;');
    expect(configGrid).toContain('gap: var(--space-7);');
  });

  it('uses labelled icon controls and keeps the product heading hierarchy', () => {
    const hero = readSource('web/src/components/hero.tsx');
    const dashboard = readSource('web/src/components/dashboard-page.tsx');

    expect(hero).toContain('<Icon name="globe" /> DDNS Pro 多域名管理');
    expect(hero).toContain('<Icon name="help" /> {usageOpen ? \'收起说明\' : \'使用说明\'}');
    expect(dashboard).toContain('<Icon name="database" /> IP 池工作台');
    expect(dashboard).toContain('<Icon name="dashboard" /> 运行活动');
    expect(dashboard).toContain('<Icon name="activity" /> {checkingBatch ? \'检测中…\' : \'检测\'}');
    expect(dashboard).toContain('<Icon name="save" /> {savingPool ? \'保存中…\' : \'入库\'}');
  });
});
