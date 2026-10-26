/** 两种排序共用本地草稿流程；保存只到内存替身。 */
export async function auditOrderFlow(cdp, sessionId, surface, requests, fixture, capture) {
  const failures = [];
  const check = (value, message) => { if (!value) failures.push(message); };
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const original = { pools: structuredClone(fixture.pools), bindings: structuredClone(fixture.bindings.items),
    delay: fixture.orderSaveDelay, failure: fixture.failOrderSave };
  const keypress = async (key, extra = {}) => {
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key, ...extra }, sessionId);
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key, ...extra }, sessionId);
  };
  try {
    for (const kind of ['bindings', 'pools']) {
      const prefix = kind === 'pools' ? 'pool-order' : 'domain-pool-order';
      const list = `#${prefix}-list`;
      const title = kind === 'pools' ? '自定义池排序' : '自定义绑定池排序';
      const items = kind === 'pools' ? original.pools.filter(item => !['ip_pool_default', 'ip_pool_trash'].includes(item.key)) : original.bindings;
      const names = items.map(item => kind === 'pools' ? item.name : item.domain);
      const savedKeys = () => read(kind === 'pools'
        ? '[...document.querySelector("#pool-selector").options].map(item => item.value)'
        : '[...document.querySelectorAll(".domain-binding-card tbody .domain-binding-name")].map(item => item.textContent.trim())');
      const baseline = await savedKeys();
      const listNames = () => read(`[...document.querySelectorAll('${list} .pool-order-name strong')].map(item => item.textContent.trim())`);
      const route = kind === 'pools'
        ? (surface === 'main' ? '/api/save-pool-order' : '/api/pools/order')
        : (surface === 'main' ? '/api/save-domain-pool-order' : '/api/domain-bindings/order');
      const writes = () => requests.filter(request => request.surface === surface && request.path === route && ['POST', 'PUT'].includes(request.method));
      const before = writes().length;
      const open = async () => {
        if (kind === 'pools') {
          await click('.action-menu-trigger');
          if (surface === 'main') await click('[onclick="runPoolMenuAction(\'order\')"]');
          else {
            const index = await read('[...document.querySelectorAll(".action-menu-item")].findIndex(item => item.textContent.includes("自定义池排序"))');
            if (index < 0) throw new Error('池菜单缺少 main 的自定义池排序操作');
            await click(`.action-menu-item:nth-child(${index + 1})`);
          }
        } else await click(surface === 'main' ? '[onclick*="openDomainPoolOrderDialog()"]' : '.domain-binding-actions button:first-child');
        await cdp.until(sessionId, `Boolean(document.querySelector('${list}')?.offsetWidth)`);
        await read('Promise.all(document.querySelector(".pool-order-modal").getAnimations().map(animation => animation.finished)).then(() => true)');
        check(await read(`document.querySelector('.custom-modal-title').textContent.includes('${title}')`), `${title}标题不符`);
      };
      await open();
      await capture?.(`${kind}-order`);
      check(JSON.stringify(await listNames()) === JSON.stringify(names), `${title}没有以保存的顺序初始化草稿`);
      check(await read(`document.querySelector('${list} [data-action="up"][data-index="0"]').disabled
        && document.querySelector('${list} [data-action="down"][data-index="${items.length - 1}"]').disabled`), `${title}首尾移动按钮未禁用`);
      if (kind === 'pools') check(await read(`document.querySelectorAll('${list} .pool-order-item').length === ${items.length}`), '默认池和垃圾桶不能进入可移动列表');
      if (surface === 'current') {
        check(await read(`(() => {
          const dialog = document.querySelector('.pool-order-modal');
          const box = dialog.getBoundingClientRect();
          return box.left >= 0 && box.top >= 0 && box.right <= innerWidth && box.bottom <= innerHeight
            && document.documentElement.scrollWidth <= innerWidth
            && [...dialog.querySelectorAll('button:not(:disabled)')].every(button => button.getBoundingClientRect().width >= 32 && button.getBoundingClientRect().height >= 32)
            && [...dialog.querySelectorAll('.pool-order-item')].every(row => row.querySelector('.pool-order-name').getBoundingClientRect().right <= row.querySelector('.pool-order-actions').getBoundingClientRect().left);
        })()`), `${title}在当前视口溢出、文字重叠或点击目标过小`);
        check(await read('document.querySelector(".pool-order-modal").contains(document.activeElement)'), '排序弹窗没有获得键盘焦点');
        await read(`document.querySelector('#${prefix}-save').focus()`);
        await keypress('Tab', { code: 'Tab', windowsVirtualKeyCode: 9 });
        check(await read('document.querySelector(".pool-order-modal").contains(document.activeElement)'), 'Tab 焦点逃出排序弹窗');
      }
      await click(`${list} [data-action="down"][data-index="0"]`);
      const movedNames = [names[1], names[0], ...names.slice(2)];
      check(JSON.stringify(await listNames()) === JSON.stringify(movedNames), `${title}没有移动本地草稿`);
      check(writes().length === before && JSON.stringify(await savedKeys()) === JSON.stringify(baseline), `${title}调整草稿时提前写入或改变保存列表`);
      await click(`#${prefix}-cancel`);
      await cdp.until(sessionId, `!document.querySelector('${list}')`);
      if (surface === 'current') check(await read(`document.activeElement.id === '${kind === 'pools' ? 'pool-action-trigger' : 'domain-order-trigger'}'`), '取消后没有把焦点归还给排序入口');
      await open();
      check(JSON.stringify(await listNames()) === JSON.stringify(names), `${title}重新打开没有丢弃取消的草稿`);
      await click(`${list} [data-action="down"][data-index="0"]`);
      check(await read('document.elementFromPoint(8, 8).classList.contains("custom-modal-overlay")'), '排序弹窗背景未覆盖当前视口');
      await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', button: 'left', clickCount: 1, x: 8, y: 8 }, sessionId);
      await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', button: 'left', clickCount: 1, x: 8, y: 8 }, sessionId);
      await cdp.until(sessionId, `!document.querySelector('${list}')`);
      if (surface === 'current') {
        await open();
        await click(`${list} [data-action="down"][data-index="0"]`);
        await keypress('Escape', { code: 'Escape', windowsVirtualKeyCode: 27 });
        await cdp.until(sessionId, `!document.querySelector('${list}')`);
      }
      check(writes().length === before && JSON.stringify(await savedKeys()) === JSON.stringify(baseline), `${title}取消或背景关闭产生了写入`);
      await open();
      await click(`${list} [data-action="down"][data-index="0"]`);
      fixture.failOrderSave = kind;
      fixture.orderSaveDelay = 250;
      await click(`#${prefix}-save`);
      await cdp.until(sessionId, `document.querySelector('#${prefix}-save')?.disabled`);
      if (surface === 'current') check(await read('!document.querySelector(".pool-order-modal button:not(:disabled)")'), '保存期间仍可修改或关闭排序草稿');
      await cdp.until(sessionId, `!document.querySelector('#${prefix}-save')?.disabled && document.body.innerText.includes('模拟排序保存失败')`);
      check(writes().length === before + 1 && JSON.stringify(await listNames()) === JSON.stringify(movedNames), `${title}失败后丢失草稿或重复提交`);
      check(JSON.stringify(await savedKeys()) === JSON.stringify(baseline), `${title}失败时改变了保存列表`);
      await click(`#${prefix}-save`);
      await cdp.until(sessionId, `!document.querySelector('${list}')`);
      const order = [items[1].key, items[0].key, ...items.slice(2).map(item => item.key)];
      const expected = kind === 'pools' ? ['ip_pool_default', ...order, 'ip_pool_trash'] : order;
      check(writes().length === before + 2 && writes().slice(before).every(request => JSON.stringify(request.input.order) === JSON.stringify(expected)), `${title}保存重试没有提交完整草稿顺序`);
      await cdp.until(sessionId, kind === 'pools'
        ? `JSON.stringify([...document.querySelector('#pool-selector').options].map(item => item.value)) === ${JSON.stringify(JSON.stringify(expected))}`
        : `JSON.stringify([...document.querySelectorAll('.domain-binding-name')].map(item => item.textContent.trim())) === ${JSON.stringify(JSON.stringify(movedNames))}`);
      check(JSON.stringify(fixture.config.targets.map(item => `${item.domain}|${item.mode}`)) === JSON.stringify(original.bindings.map(item => item.key)), '绑定显示排序改变了维护执行顺序');
    }
  } finally {
    fixture.pools = original.pools;
    fixture.bindings.items = original.bindings;
    fixture.orderSaveDelay = original.delay;
    fixture.failOrderSave = original.failure;
  }
  return failures;
}

/** 长列表与不足两个条目的边界；每轮恢复夹具，避免污染 main 对照。 */
export async function auditOrderEdges(cdp, sessionId, base, requests, fixture, capture) {
  const original = structuredClone(fixture);
  const failures = [];
  const read = expression => cdp.evaluate(sessionId, expression);
  const click = selector => cdp.click(sessionId, selector);
  const check = (condition, message) => { if (!condition) failures.push(message); };
  const writesBefore = requests.filter(request => ['/api/pools/order', '/api/domain-bindings/order'].includes(request.path)).length;
  const navigate = async () => {
    await cdp.send('Page.navigate', { url: base }, sessionId);
    await cdp.until(sessionId, `document.querySelector('#pool-selector')?.options.length === ${fixture.pools.length}
      && document.querySelector('.target-summary-domain')?.textContent === ${JSON.stringify(fixture.config.targets[0].domain)}`);
    await cdp.until(sessionId, 'document.querySelectorAll("#status-table .address-pill").length === 2');
  };
  const open = async kind => {
    if (kind === 'pools') {
      await click('#pool-action-trigger');
      const index = await read('[...document.querySelectorAll(".action-menu-item")].findIndex(item => item.textContent.includes("自定义池排序"))');
      await click(`.action-menu-item:nth-child(${index + 1})`);
    } else await click('#domain-order-trigger');
  };
  try {
    const defaults = original.pools.find(pool => pool.key === 'ip_pool_default');
    const trash = original.pools.find(pool => pool.key === 'ip_pool_trash');
    fixture.pools = [defaults, ...Array.from({ length: 24 }, (_, index) => ({
      key: `ip_pool_${String(index + 1).padStart(3, '0')}`, name: `香港电信移动联通共同备用出口节点-长名称验证-${index + 1}`, count: 2,
    })), trash];
    fixture.config.targets = Array.from({ length: 20 }, (_, index) => ({ ...original.config.targets[0],
      domain: `very-long-managed-target-name-for-narrow-layout-${index}.example.com`,
      prefix: `very-long-managed-target-name-for-narrow-layout-${index}`, mode: 'A', enabled: true,
    }));
    fixture.bindings.items = fixture.config.targets.map(target => ({ key: `${target.domain}|A`, domain: target.domain,
      mode: 'A', enabled: true, poolKey: defaults.key, poolName: defaults.name }));
    fixture.records = Object.fromEntries(fixture.config.targets.map(target => [`${target.domain}|A`,
      original.records[`${original.config.targets[0].domain}|A`].map(record => ({ ...record, name: target.domain }))]));
    fixture.configDelay = 0;
    fixture.probeDelay = 0;
    await navigate();
    for (const kind of ['pools', 'bindings']) {
      const prefix = kind === 'pools' ? 'pool-order' : 'domain-pool-order';
      await open(kind);
      await cdp.until(sessionId, `Boolean(document.querySelector('#${prefix}-list')?.offsetWidth)`);
      await read('Promise.all(document.querySelector(".pool-order-modal").getAnimations().map(animation => animation.finished)).then(() => true)');
      const metrics = await read(`(() => {
        const dialog = document.querySelector('.pool-order-modal');
        const list = document.querySelector('#${prefix}-list');
        const box = dialog.getBoundingClientRect();
        return { fits: box.top >= 0 && box.left >= 0 && box.right <= innerWidth && box.bottom <= innerHeight,
          scrolls: list.scrollHeight > list.clientHeight && getComputedStyle(list).overflowY === 'auto',
          namesFit: [...list.querySelectorAll('.pool-order-item')].every(row =>
            row.querySelector('.pool-order-name').getBoundingClientRect().right <= row.querySelector('.pool-order-actions').getBoundingClientRect().left),
          fullNames: [...list.querySelectorAll('strong')].every(name => name.title === name.textContent),
          footerVisible: [...dialog.querySelectorAll('.custom-modal-buttons button')].every(button => button.getBoundingClientRect().bottom <= innerHeight),
          x: list.getBoundingClientRect().left + list.clientWidth / 2, y: list.getBoundingClientRect().bottom - 20 };
      })()`);
      check(metrics.fits && metrics.scrolls && metrics.namesFit && metrics.fullNames && metrics.footerVisible,
        `${kind} 长名称或长列表布局不合格：${JSON.stringify(metrics)}`);
      await cdp.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: metrics.x, y: metrics.y, deltaX: 0, deltaY: 700 }, sessionId);
      await cdp.until(sessionId, `document.querySelector('#${prefix}-list').scrollTop > 0`);
      await capture?.(`${kind}-order-long`);
      await click(`#${prefix}-cancel`);
      await cdp.until(sessionId, '!document.querySelector(".pool-order-modal")');
    }
    fixture.pools = [defaults, fixture.pools[1], trash];
    fixture.config.targets = fixture.config.targets.slice(0, 1);
    fixture.bindings.items = fixture.bindings.items.slice(0, 1);
    await navigate();
    for (const kind of ['pools', 'bindings']) {
      await open(kind);
      await cdp.until(sessionId, `document.body.innerText.includes('${kind === 'pools' ? '至少需要两个自定义池才能排序' : '至少需要两个管理域名才能排序'}')`);
      check(await read('!document.querySelector(".pool-order-modal")'), `${kind} 单条目不应建立排序草稿`);
    }
    fixture.pools = [defaults, trash];
    await navigate();
    await open('pools');
    await cdp.until(sessionId, 'document.body.innerText.includes("至少需要两个自定义池才能排序")');
    check(requests.filter(request => ['/api/pools/order', '/api/domain-bindings/order'].includes(request.path)).length === writesBefore,
      '长列表取消或不足两条目的提示产生了写入');
  } finally {
    Object.assign(fixture, original);
  }
  return failures;
}
