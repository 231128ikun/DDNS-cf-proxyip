# 参与开发

## 先读这两份约定

- [AGENTS.md](./AGENTS.md)：一套程序、数据格式、分层依赖与验证门禁的完整规则。
- [README.md](./README.md)：部署方式、配置说明与仓库结构。

## 分支与提交

- 分支名用 `codex/<简短主题>`。
- 提交信息用 `feat:`、`fix:`、`refactor:`、`docs:`、`chore:`；一次提交只做一件事。
- 不提交构建产物、`_worker.js`、`dist/`、缓存、sourcemap、截图或任何密钥。

## 改代码时注意

1. 源码只有 `app/`：Worker 在 `app/src/`，面板在 `app/web/`，两个目录之外不放业务代码。
2. 依赖方向固定：`transport/jobs -> application -> domain + ports <- adapters`；业务规则不依赖 HTTP、KV、fetch 或页面。
3. 相同规则只保留一份实现；新增抽象必须有真实复用点或替换点，没有用途就删除。
4. 探针异常（超时、HTTP 错误、坏 JSON、未知响应）只能记 `unknown`，不能把节点判成失效。

## 提交前必须通过

```powershell
cd app
npm run check     # 类型检查 + 单元测试 + 构建 + 体积门禁
npm run smoke     # 静态资源与 /api/* 的分工
```

改动面板或样式时额外执行（`npm run dev` 另开一个终端）：

```powershell
npm run audit:ui
```

体积超预算时先删重复实现或收紧设计，不允许直接抬高预算。
