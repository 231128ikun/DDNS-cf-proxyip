import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { launchBrowser } from './ui-browser.mjs';
import { comparePixels } from './pixel-diff.mjs';

// Consume the actual paired captures, without modifying either application's DOM.
const input = resolve(process.argv[2] ?? '.wrangler/tmp/ui-visual/report.json');
const output = resolve('.wrangler/tmp/ui-pixels');
const report = JSON.parse(readFileSync(input, 'utf8'));
mkdirSync(output, { recursive: true });
const results = [];
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;');
let browser;
try {
  browser = await launchBrowser();
  const { cdp } = browser;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Runtime.enable', {}, sessionId);
  for (const viewport of report.results) {
    const reference = viewport.sessions.find(session => session.name === 'main');
    const current = viewport.sessions.find(session => session.name === 'current');
    if (!reference || !current) throw new Error(`Missing pair: ${viewport.width}`);
    const states = Object.keys(reference.images ?? {});
    if (!states.length) throw new Error(`Missing captures: ${viewport.width}`);
    for (const state of states) {
      if (!current.images?.[state]) throw new Error(`Missing current capture: ${viewport.width}/${state}`);
      const names = [reference.images[state], current.images[state]];
      const sources = names.map(name => `data:image/png;base64,${readFileSync(join(dirname(input), name)).toString('base64')}`);
      const data = await cdp.evaluate(sessionId, `(async () => {
        const images = await Promise.all(${JSON.stringify(sources)}.map(async source => {
          const image = new Image(); image.src = source; await image.decode(); return image;
        }));
        const width = Math.max(...images.map(image => image.naturalWidth));
        const height = Math.max(...images.map(image => image.naturalHeight));
        const canvas = document.createElement('canvas'); canvas.width = width; canvas.height = height;
        const context = canvas.getContext('2d', { willReadFrequently: true });
        const pixels = images.map(image => {
          context.clearRect(0, 0, width, height); context.drawImage(image, 0, 0);
          return context.getImageData(0, 0, width, height).data;
        });
        const { diff, changed, total, maxChannelDelta } = (${comparePixels.toString()})(...pixels);
        context.putImageData(new ImageData(diff, width, height), 0, 0);
        return { changed, total, maxChannelDelta, width, height, sizes: images.map(image => [image.naturalWidth, image.naturalHeight]),
          png: canvas.toDataURL('image/png').split(',')[1] };
      })()`);
      const { png, ...metrics } = data;
      const prefix = `${viewport.width}-${state}`;
      const files = [`${prefix}-main.png`, `${prefix}-current.png`, `${prefix}-diff.png`];
      names.forEach((name, index) => writeFileSync(join(output, files[index]), readFileSync(join(dirname(input), name))));
      writeFileSync(join(output, files[2]), Buffer.from(png, 'base64'));
      const passed = data.changed === 0 && JSON.stringify(data.sizes[0]) === JSON.stringify(data.sizes[1]);
      results.push({ viewport: viewport.width, state, ...metrics, passed, files });
      console.log(`${prefix}: ${passed ? 'PASS' : 'FAIL'} ${data.changed}/${data.total} pixels (${(100 * data.changed / data.total).toFixed(2)}%) differ; ${data.sizes.map(size => size.join('x')).join(' vs ')}`);
    }
  }
  if (!results.length) throw new Error('No paired screenshots');
  writeFileSync(join(output, 'report.json'), JSON.stringify({ reference: report.reference, capturedAt: report.generatedAt,
    comparedAt: new Date().toISOString(), captureConditions: report.captureConditions ?? null, tolerance: 0, ignoredRegions: [], results }, null, 2));
  writeFileSync(join(output, 'index.html'), `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>DDNS Pro pixel comparison</title>
    <style>body{font:16px sans-serif;margin:24px}section{margin-bottom:32px}div{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}img{width:100%;border:1px solid #ddd}figure{margin:0}</style>
    <h1>Strict pixel comparison</h1><p>Reference: ${escape(report.reference)}. No tolerance or ignored regions. Every pixel in the supplied captures is compared.</p>
    <p>Capture conditions: ${escape(JSON.stringify(report.captureConditions ?? 'Legacy capture: dynamic content was not normalized'))}</p>
    ${results.map(result => `<section><h2>${escape(result.viewport)} / ${escape(result.state)}: ${result.passed ? 'PASS' : 'FAIL'} — ${result.changed} pixels / ${(100 * result.changed / result.total).toFixed(2)}%</h2><div>${result.files.map((file, index) => `<figure><figcaption>${['main', 'current', 'difference'][index]}</figcaption><a href="${escape(file)}"><img src="${escape(file)}" loading="lazy"></a></figure>`).join('')}</div></section>`).join('')}</html>`);
  console.log(`Report: ${join(output, 'index.html')}`);
  process.exitCode = results.every(result => result.passed) ? 0 : 1;
} finally {
  await browser?.close();
}
