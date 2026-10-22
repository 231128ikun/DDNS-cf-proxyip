# DDNS Pro Worker 维护规范

本仓库只维护一套程序：`app/` 是可维护源码和唯一实现来源。浏览器端由 Cloudflare 静态资源直接分发，`/api/*` 由唯一 Worker 处理，仓库不提交任何构建产物。不得把迁移过程命名成 v1/v2，也不得建立平行产品。

## 1. 总原则

1. **一套程序**：不得新增第二套 API、配置 key、数据格式、前端入口或部署入口。
2. **能复用就复用**：相同规则只保留一个来源，优先复用纯函数、契约和适配器。
3. **一次改动只做一件事**：纯重构、迁移、修 bug、加功能分属不同提交；重构批次不得夹带新功能。
4. **足够精简**：所有设计都要考虑 Cloudflare Workers 的体积、冷启动、CPU、子请求数、KV 操作和内存。
5. **精简不等于多拆**：模块和抽象必须对应真实复用点或替换点；没有用途就删除。
6. **依赖单向**：`transport/jobs -> application -> domain + ports <- adapters`。业务规则不依赖 HTTP、KV、fetch 或页面。
7. **安全失败**：只有可信探针明确拒绝节点时才标记 `dead`；超时、HTTP 错误、坏 JSON、TLS 错误和未知响应一律为 `unknown`。
8. **最小依赖**：新增依赖前先尝试复用现有代码。不要为了少量功能引入重型框架或运行时校验库。
9. **先测后合**：边界规则要有单元测试；不要用修一个坏一个的方式接功能。
10. **不留死代码**：未使用的文件、导出、组件、样式和兼容分支必须删除，不能以“以后可能用到”为由保留。
11. **文档描述事实**：不要写计划中的功能，不要保留会造成“两套程序”误解的历史命名。

## 2. 仓库结构

| 路径 | 用途 |
| --- | --- |
| `app/src/contracts/` | 跨层类型、API 输入输出与轻量手写校验 |
| `app/src/domain/` | 地址、目标、探针结果、IP 池等纯业务规则 |
| `app/src/application/` | 用例编排；不直接访问 `env`、KV 或 `fetch` |
| `app/src/ports/` | 存储、探针、DNS、通知等接口 |
| `app/src/adapters/` | KV、Cloudflare DNS、探针、Telegram 等外部实现 |
| `app/src/transport/` | HTTP 路由、鉴权、请求校验和错误映射 |
| `app/src/jobs/` | cron 与手动维护共用的任务入口 |
| `app/src/config/` | 环境变量解析和运行时适配器装配 |
| `app/src/index.ts` | 唯一 Worker 入口：导入运行时模块并装配 `createWorker` |
| `app/src/worker.ts` | Worker 装配实现，`fetch` 与 `scheduled` 共用；供测试直接调用 |
| `app/web/` | 浏览器端源码，与 Worker 由同一次构建生成 |
| `app/scripts/` | 构建、清理、体积门禁和 UI 验收，不进入发布文件 |
| `app/dist/web/` | 前端构建产物，部署时作为 Workers 静态资源目录；不提交 |
| `wrangler.toml` | 部署配置：Worker 入口为 `app/src/index.ts`，静态资源目录为 `app/dist/web` |

### 2.1 当前代码入口

| 任务 | 首选入口 |
| --- | --- |
| Worker 装配 | `app/src/index.ts`、`app/src/worker.ts` |
| HTTP 路由与鉴权 | `app/src/transport/http.ts`、`auth.ts`、`router.ts` |
| 单节点与批量检测 | `app/src/application/check-proxy.ts`、`check-pool.ts` |
| 探针实现 | `app/src/adapters/probe/`、`app/src/config/runtime.ts` |
| 配置读写 | `app/src/contracts/config.ts`、`app/src/application/config-service.ts`、`app/src/adapters/storage/kv-config-repository.ts` |
| IP 池 | `app/src/application/pool-service.ts`、`app/src/domain/pool-entry.ts`、`app/src/adapters/storage/kv-pool-catalog.ts` |
| 域名绑定 | `app/src/application/domain-bindings.ts`、`app/src/adapters/storage/kv-domain-binding-repository.ts` |
| DNS 维护 | `app/src/application/maintain-managed-target.ts`、`maintain-managed-targets.ts`、`app/src/adapters/dns/cloudflare-dns.ts` |
| Telegram | `app/src/adapters/notify/` |
| 浏览器端 | `app/web/src/`，页面入口为 `app.tsx`，请求统一走 `api/client.ts` |
| 发布构建 | `app/scripts/build-worker.mjs`，构建前端并产出 `app/dist/release/worker.js` 供体积门禁检查 |

## 3. 开始任务前

至少检查：

```powershell
git status --short --branch
git log -5 --oneline
cd app
npm run typecheck
```

如果工作区已有用户改动，不得执行 `git reset --hard`、`git clean`、覆盖文件或删除用户内容。需要同步远端且工作区干净时，才使用 `git fetch origin` 和 `git pull --ff-only`。

## 4. 数据与行为约定

KV 绑定名固定为：

```text
IP_DATA
```

主要 KV key：

- `app_config`：面板配置、域名区域、维护目标与运行时参数；
- `ip_pool_default`：默认 IP 池；
- `ip_pool_###`：自定义 IP 池；
- `ip_pool_trash`：垃圾桶；
- `domain_pool_mapping`：域名与 IP 池绑定；
- `domain_pool_order`：域名显示顺序；
- `ip_pool_names`：池 ID 与显示名称；
- `ip_pool_order`：池显示顺序。
- pool_stats_baseline：距上次成功通知的各池数量基线，只在维护通知成功发送后更新。

IP 池标准格式：

```text
ip:port,asn,country,stack # 可选备注
```

- IPv6 带端口必须写成 `[IPv6]:port`；
- `stack` 标准值为 `v4`、`v6`、`v4/v6`；
- 未知值使用 `null`；
- 旧的两字段、三字段和备注格式必须继续可读；
- 更新检测结果时，不得用 `null` 或 `unknown` 覆盖已有有效元数据；
- 合并同一地址时保留有效元数据和用户备注。

配置读取顺序：

1. 优先读取 KV 的 `app_config`；
2. KV 不存在或不可解析时使用环境变量和内置默认值；
3. 保存永远写回 `app_config`，不得创建平行配置。

必须区分：

1. **真实失效**：可信探针正常返回节点不可用；
2. **探针异常**：超时、网络错误、HTTP 错误、坏 JSON 或未知响应。

探针异常不能删除 DNS、不能把节点移入垃圾桶。主接口异常时才按既有规则尝试备用接口。

DNS 规则：

- 地址模式维护 `A` / `AAAA`，不能套用 TXT 的端口逻辑；
- TXT 模式维护单条记录内的地址列表；
- 出口国家、ASN 或栈不匹配可以移出目标 DNS，但不能当作死节点入垃圾桶；
- 补货候选不能重复添加当前已生效的地址。

垃圾桶只有一条写入入口：所有入桶都必须经过统一的去重、上限截断和注释格式实现，面板、维护流程和恢复流程不得各写一套。

## 5. 前端规范

- 浏览器端只使用 `app/web/`，不得把大段 HTML、CSS 和脚本塞回 Worker 路由。
- 请求统一走 `app/web/src/api/client.ts`，不要在页面组件里重复 fetch、鉴权、错误解析代码。
- 视觉语义只有一个来源：颜色、间距、圆角、字号和阴影由 `app/web/src/styles.css` 的语义变量定义，页面组件只引用语义名，不写孤立尺寸。
- 可复用的展示单元（状态徽标、卡片、表单行、菜单、弹窗、提示）先抽成组件，再在页面组合；同类控件不得出现两套样式实现。
- 页面视觉与操作流程保持 DDNS Pro 现有风格；改动应按功能块收敛，不另起一套设计。
- 高频动作使用“图标 + 文字”；次级、危险和菜单动作以文字为主，避免图标堆叠。
- 必须同时验证桌面和窄屏；文本不能溢出或与操作区重叠。
- 图标必须有可访问名称，表单控件必须有关联标签，标题层级不能跳级。

页面或样式改动后至少运行：

```powershell
npm run build
npm run audit:ui
```

## 6. 配置与安全

不得提交真实 Cloudflare Token、Zone ID、Telegram Token、Chat ID、KV Namespace ID，也不得在回复或日志中回显密钥。

环境变量只是 KV 为空时的启动配置和故障回退，不是第二套配置模型。所有外部请求必须有超时、失败处理和备用逻辑。

不擅自调用真实的 DNS 删除、KV 清空、垃圾桶清空或全量维护接口。真实写操作需要用户明确许可。

## 7. 构建与部署

```powershell
cd app
npm ci
npm run build
```

构建流程：

1. Vite 构建 `app/web/` 到 `app/dist/web/`；
2. Wrangler 打包 `app/src/index.ts`，产物 `app/dist/release/worker.js` 只用于体积门禁与检查。

部署形态：

- 面板是 Cloudflare 静态资源（目录 `app/dist/web/`），由边缘直接分发；
- Worker 只处理 `/api/*`，前端不再打包进 Worker；
- 通过 `npm run deploy` 或 Cloudflare Git 集成部署；构建命令为 `cd app && npm ci`，部署命令为 `cd app && npm run deploy`，部署脚本必须先跑完整 `npm run check`；
- 仓库不提交 `_worker.js` 或任何构建产物，也不再提供“复制单个文件到控制台”的部署方式。

构建产物、源码、测试、sourcemap、截图、`node_modules/`、`.wrangler/` 或缓存不得进入版本库，也不得进入静态资源目录。

## 8. 验证要求

普通代码改动至少运行：

```powershell
cd app
npm run typecheck
npm run test
npm run build
npm run check:size
git diff --check
git status --short
```

提交前完整门禁：

```powershell
cd app
npm run check
```

`npm run check` 必须依次完成类型检查、接口契约测试、单元测试、构建、体积门禁和部署形态冒烟。接口契约测试必须证明所有 Web API 客户端方法都有对应的 Worker 路由；冒烟测试必须证明同一次构建下首页由静态资源返回、`/api/health` 可用、未知 API 返回 JSON 404。体积门禁分两条：Worker 打包体积和首屏页面重量（JS 与 CSS 的 gzip 合计）。体积超预算时先删除重复实现、减少依赖或调整设计；确因功能增长需要调整预算时，单次放宽不得超过 20%，并同步说明余量，禁止连续追涨掩盖体量膨胀。

UI 改动额外验证桌面与窄屏；涉及 KV、探针或 DNS 改动时增加对应模拟测试，不能用静态语法检查代替行为验证。

## 9. Git 与交付

- 默认使用 `codex/<简短主题>` 分支；
- 提交信息使用 `feat:`、`fix:`、`refactor:`、`docs:`、`chore:`；
- 不擅自合并、打标签或部署；
- 提交前确认没有密钥、缓存、构建中间文件和其他项目内容；
- 最终说明修改内容、验证结果和未验证风险。

## 10. 完成检查

- [ ] 仍然只有一套源码、API、配置和 KV 数据；
- [ ] 没有新增平行入口或重复业务实现；
- [ ] 前端仍属于同一个 DDNS Pro，视觉语义只有一套来源；
- [ ] 没有提交 `_worker.js`、`dist/`、缓存、sourcemap 或测试杂物；
- [ ] `wrangler.toml` 的 Worker 入口与静态资源目录与实际构建一致；
- [ ] KV、旧池格式、垃圾桶单一写入入口和 `unknown` 安全语义未被破坏；
- [ ] A/AAAA 与 TXT 两种模式都已考虑；
- [ ] `npm run check` 通过；
- [ ] `git diff --check` 通过；
- [ ] 最终工作区范围已复核。
