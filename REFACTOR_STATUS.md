# 重构状态

> [!WARNING]
> **本分支仍在重构中。** 不要把本分支当作稳定版本，也不要直接覆盖 `main`。合并前需要通过 Pull Request。

## 当前状态

- 状态：最终代码审查已完成，待推送与 PR
- 稳定分支：`main`
- 重构分支：`codex/modular-refactor`
- 目标：保持 DDNS Pro 一套源码、一套 API 和一套 KV 数据，把原来的单文件实现拆分为可测试、可维护的模块。
- 合并方式：推送分支后通过 Pull Request 合并到 `main`。

## 已完成

- Worker 源码从单文件拆分为 `contracts / domain / application / ports / adapters / transport / jobs / config`。
- 浏览器端从 Worker 字符串模板迁移到 `app/web/` 的 Preact 源码。
- 面板改为 Cloudflare Workers Static Assets：`app/dist/web` 是静态资源目录，Worker 只处理 `/api/*`。
- 仓库不再提交 `_worker.js`；`wrangler.toml` 的入口是 `app/src/index.ts`。
- 新增部署形态冒烟检查 `npm run smoke`，验证静态资源、API 路由和缺失资源 404 行为。
- 移除重构期间夹带的 socket 探针、composite 探针和接口自检。
- 一键洗库恢复为服务端用例：读池、检测、有效项写回、失效项统一入桶，未确认项不落盘。
- 新增 `pool_stats_baseline`：维护报告按“距上次成功通知”对比各池数量，通知发送失败或未发送时不回写基线。
- 面板不再直接写入垃圾桶：保存接口拒绝 `ip_pool_trash`，垃圾桶只保留去重、截断和注释格式统一的单一写入入口。
- 恢复 `txt@域名` 与域名 A/AAAA 解析探测：DoH 适配器 + 解析用例 + 统一探测入口（`POST /api/check`），解析失败只提示错误、不会把节点判成失效。
- 配置项收敛：删除不会被消费的 `CONCURRENT_CHECKS`、`DOH_TIMEOUT`、`dohApi` 与 `DOH_API`；`BACKEND_CONCURRENT_CHECKS` 真正驱动批量检测与维护并发。
- 前端颜色、间距、圆角、字号和阴影已收敛为语义变量，并抽取统一的记录类型徽标组件；未使用变量与不可达规则已删除。
- 最终审查发现的问题已修：垃圾桶写入入口、空转配置项、未使用导出与过期注释、面板与 README 对探测能力的描述。
- 维护补货改为有界探索：只探测一个有上限的候选窗口（按需数量的 2 倍 + 1，最多 12 个），再按“能补位 + 延迟”排序取最优，避免全失效的池一路探测到池底打满子请求。
- 新增 [`docs/ip-pool-design.md`](./docs/ip-pool-design.md)：记录参考项目的做法、KV 与 D1 的取舍和后续优先级。

## 待完成

- 推送 `codex/modular-refactor` 并创建 Pull Request（需用户确认后再执行）。
- PR 描述中说明破坏性变更：旧 `/api/*` 接口面被替换；面板不再提供 DNS 记录列表与手动增删；开启 `AUTH_KEY` 时面板静态页面本身不受保护，只有 `/api/*` 受保护。
- 已知遗留：只有注释的池行在批量检测中记为 `invalid`，而解析与洗库按可保留内容处理，四条路径规则不一致（`main` 上同样存在）。

## 最近验证（2026-10-16）

在 `app/` 下运行：

```powershell
npm run check
npm run smoke
npm run audit:ui
```

结果：

- 类型检查通过。
- 单元测试通过：27 个测试文件、196 项测试。
- 构建通过，体积门禁通过。
- Worker 打包体积：140.21 KB raw / 33.60 KB gzip。
- 首屏 js + css 合计：95.11 KB raw / 29.78 KB gzip；其中 CSS 28.45 KB raw。
- 冒烟检查通过：`/` 返回静态面板，`/api/health` 返回 Worker JSON，缺失 JS/CSS 返回 404。
- UI 验收通过：375 / 768 / 992 / 1265 四档无横向溢出、对比度失败、小于 32px 点击目标或 a11y 问题。
- 本机开发环境没有出网能力，DoH 真机链路未验证：适配器与解析用例由 mock fetch 单测覆盖，本地只验证到"解析失败返回明确错误、不影响节点状态"。

## 工作区说明

- `<main-checkout>` 检出稳定分支 `main`。
- `<refactor-worktree>` 是同一仓库的 worktree，检出 `codex/modular-refactor`。
- 两个目录共享 Git 对象库，但工作区独立，互不覆盖。
