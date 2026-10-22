# 重构分支状态

> [!NOTE]
> `codex/modular-refactor` 是当前维护实现；`main` 仍是旧版入口，不得作为新前端或新 Worker 的部署来源。

## 当前状态

- 状态：当前实现已推送到 `origin/codex/modular-refactor`
- 部署目标：Cloudflare `ikun01` 账户的 `ddns-pro-refactor` Worker
- Worker 入口：`app/src/index.ts`；面板源码：`app/web/`
- 部署形态：面板是 Cloudflare 静态资源（`app/dist/web`），Worker 只处理 `/api/*`

## 相对 main 的变化（部署前必读）

- 旧 `/api/*` 接口面被替换；面板不再提供 DNS 记录列表与手动增删记录。
- 当前测试阶段未启用面板 key 校验，`/api/*` 可直接访问；只应部署到测试账户，不得在公开实例保存生产凭据。
- 仓库不再提交 `_worker.js`，不再支持“复制单文件到 Worker 编辑器”的部署方式。
- 新增 `POST /api/check` 统一探测入口：IP/带端口目标直接探测，裸域名解析 A/AAAA，`txt@域名` 读取 TXT 列表。

## 已完成

- Worker 源码拆分为 `contracts / domain / application / ports / adapters / transport / jobs / config`，依赖单向。
- 面板改为 `app/web/` 的 Preact 源码，样式收敛为语义变量，并抽取复用组件。
- 面板由 Workers Static Assets 分发，`npm run smoke` 校验“静态资源 + `/api/*`”分工，并实际调用批量检测的 JSON、NDJSON 与超限 400 路径。
- 移除重构期间夹带的 socket 探针与接口自检。
- 一键洗库为服务端用例；垃圾桶只保留统一写入入口。
- 批量检测按每批 4 个唯一地址拆分请求并合并进度；进度流无法完整结束时，当前批自动退回普通 JSON 请求，避免大批量输入触发单次 Worker 限制。
- 维护通知按“距上次成功通知”的池数量基线对比。
- 维护补货改为有界探索窗口并按延迟择优，避免全失效的池探测到池底。
- 死代码、不可达样式、空转配置项已清理；文档与实际行为对齐。
- IP 池与存储取舍记录在 [`ip-pool-design.md`](./ip-pool-design.md)。

## 验证入口

在 `app/` 下运行 `npm run check`、`npm run audit:ui`。接口契约测试以真实 `ApiClient -> Worker route -> application` 闭环覆盖拆批、进度和最终合并；部署形态冒烟同时检查静态资源、健康接口、批量检测 JSON/NDJSON、超限 400 与未知 API 404。
