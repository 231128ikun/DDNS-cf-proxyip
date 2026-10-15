# 重构状态

> [!WARNING]
> **本分支仍在重构中。** 不要把本分支当作稳定版本，也不要直接覆盖 `main`。合并前需要同步 `main`、完成 UI 验收和代码审查。

## 当前状态

- 状态：进行中
- 稳定分支：`main`
- 重构分支：`codex/modular-refactor`
- 目标：保持 DDNS Pro 一套源码、一套 API 和一套 KV 数据，把原来的单文件实现拆分为可测试、可维护的模块。
- 合并要求：完成 `main` 同步、测试、UI 验收和代码审查后，通过 Pull Request 合并到 `main`。

## 已完成

- Worker 源码从单文件拆分为 `contracts / domain / application / ports / adapters / transport / jobs / config`。
- 浏览器端从 Worker 字符串模板迁移到 `app/web/` 的 Preact 源码。
- 面板改为 Cloudflare Workers Static Assets：`app/dist/web` 是静态资源目录，Worker 只处理 `/api/*`。
- 仓库不再提交 `_worker.js`；`wrangler.toml` 的入口是 `app/src/index.ts`。
- 新增部署形态冒烟检查 `npm run smoke`，验证静态资源、API 路由和缺失资源 404 行为。
- 移除重构期间夹带的 socket 探针、composite 探针和接口自检。
- 一键洗库恢复为服务端用例：读池、检测、有效项写回、失效项统一入桶，未确认项不落盘。
- 新增 `pool_stats_baseline`：维护报告按“距上次成功通知”对比各池数量，通知发送失败或未发送时不回写基线。

## 待完成

- 同步 `main` 分支上的最新提交，逐条核对行为差异并处理冲突。
- 完成前端视觉语义化；继续复用组件整理，并复验桌面与窄屏 UI。
- 完成最终代码审查和 Pull Request。

## 最近验证（2026-10-16）

在 `app/` 下运行：

```powershell
npm run check
npm run smoke
```

结果：

- 类型检查通过。
- 单元测试通过：25 个测试文件、179 项测试。
- 构建通过。
- 体积门禁通过。
- Worker 打包体积：130.54 KB raw / 31.01 KB gzip。
- 冒烟检查通过：`/` 返回静态面板，`/api/health` 返回 Worker JSON，缺失 JS/CSS 返回 404。

## 工作区说明

- `<main-checkout>` 检出稳定分支 `main`。
- `<refactor-worktree>` 是同一仓库的 worktree，检出 `codex/modular-refactor`。
- 两个目录共享 Git 对象库，但工作区独立，互不覆盖。