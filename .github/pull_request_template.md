## 改动内容

<!-- 一句话说明改了什么、为什么；破坏性变更必须写清。 -->

## 验证

- [ ] `cd app && npm run check`
- [ ] `cd app && npm run smoke`
- [ ] 面板或样式改动：`npm run audit:ui`（桌面 + 窄屏）
- [ ] 涉及 KV、探针或 DNS：补了对应的模拟测试

## 仓库约束

- [ ] 仍然只有一套源码、API、配置和 KV 数据，没有新增平行入口
- [ ] 没有提交 `_worker.js`、`dist/`、缓存、sourcemap、截图或密钥
- [ ] `wrangler.toml` 的入口与静态资源目录和实际构建一致
