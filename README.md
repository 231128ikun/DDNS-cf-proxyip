# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

DDNS Pro 是一个部署在 Cloudflare Workers 上的 ProxyIP 检测、IP 池管理和 Cloudflare DNS 自动维护面板。

本仓库只有一套程序：`app/` 是可维护源码，仓库根目录的 `worker.js` 是同一程序生成的发布文件，`wrangler.toml` 是唯一部署配置。两种部署方式只是操作方式不同，不是两个版本，也不存在第二套 API、配置或数据。

## 功能

- 单个 ProxyIP 检测与 IP 池批量检测；
- 外部检测 API、CF-Workers-CheckProxyIP 兼容模式、双探针 Socket 三种检测方式；
- 地址记录模式维护 `A` / `AAAA`，TXT 模式维护地址列表；
- 自动删除真实失效节点并从 IP 池补货；
- IP 池新建、重命名、排序、删除、合并、筛选、去重与垃圾桶恢复；
- 域名与 IP 池绑定；
- cron 定时维护与手动立即维护；
- Telegram 通知；
- DDNS Pro 管理面板与配置中心。

探针结果严格区分：

- `alive`：可信探针确认节点可用；
- `dead`：可信探针明确确认节点失效；
- `unknown`：超时、网络错误、HTTP 错误、坏 JSON、TLS 失败或探针异常。

只有 `dead` 会进入删除或垃圾桶流程，`unknown` 不会按死节点处理。

## 快速部署

部署前需要一个 Cloudflare 账号和一个 KV Namespace。

### 方法一：Dashboard 手动部署

1. 打开 [Cloudflare Workers](https://dash.cloudflare.com/?to=/:account/workers)，创建一个 Worker。
2. 打开代码编辑器，把仓库根目录 [`worker.js`](./worker.js) 的全部内容复制进去。
3. 保存并部署。
4. 创建 KV Namespace，任意命名。
5. 打开 Worker 的 **Settings → Bindings**，添加 KV Namespace 绑定：

```text
Variable name: IP_DATA
```

绑定名必须填写 `IP_DATA`。前端已经打包在 `worker.js` 中，不需要 Static Assets 绑定。

6. 建议添加 `AUTH_KEY`，否则知道 Worker 地址的人都能访问管理面板。
7. 打开 Worker 地址，进入 **配置中心**，填写维护域名、Zone ID、Cloudflare API Token、检测 API 和 Telegram 等配置。
8. 如需自动维护，在 **Triggers → Cron Triggers** 添加：

```text
0 */3 * * *
```

同时要在配置中心打开自动维护开关。

以后更新时，重新运行构建并复制新的 `worker.js`。KV 数据不会受影响。

### 方法二：Fork 后通过 Cloudflare Git 构建

Fork 本身不会自动部署。只有在 Cloudflare 创建 Workers Builds 项目并连接这个 GitHub 仓库后，推送才会触发部署。

1. Fork 本仓库。
2. 在 Cloudflare 创建 KV Namespace。
3. 在 fork 的根目录 `wrangler.toml` 填入 KV Namespace ID，或在 Cloudflare 项目中手动创建同样的 `IP_DATA` 绑定：

```toml
[[kv_namespaces]]
binding = "IP_DATA"
id = "你的_KV_Namespace_ID"
```

4. 在 Cloudflare **Workers & Pages → Create → Import a repository** 中选择 fork。
5. 构建配置建议：

```text
Root directory: /
Build command: cd app && npm ci && npm run build
Deploy command: cd app && npx wrangler deploy --config ../wrangler.toml
```

6. 首次部署后，在 Worker 设置中确认 `IP_DATA` 绑定存在，并按需配置环境变量、Secret 和 cron。

仓库已经提交了生成后的 `worker.js`。即使不在 Cloudflare 构建前端，也可以让部署直接使用这个文件。

## 环境变量

环境变量是首次启动和 KV 空缺时的默认值。面板保存后的配置写入 KV 的 `app_config`，不是另一套配置。

| 变量 | 用途 |
| --- | --- |
| `AUTH_KEY` | API 与面板访问密钥 |
| `CF_KEY` | Cloudflare API Token |
| `CF_ZONEID` | 默认 Cloudflare Zone ID |
| `CF_BASE_DOMAIN` | 默认区域域名 |
| `PROBE_MODE` | `external-api`、`cmliu-check` 或 `socket` |
| `CHECK_API` | 主检测接口 |
| `CHECK_API_BACKUP` | 备用检测接口 |
| `CHECK_TIMEOUT` | 单次探针超时，默认 15000 ms |
| `SOCKET_PROBE_IPV4_URL` | Socket 模式 IPv4 探针 |
| `SOCKET_PROBE_IPV6_URL` | Socket 模式 IPv6 探针 |
| `DOH_API` | DNS over HTTPS 地址 |
| `REMOTE_LOAD_TIMEOUT` | 远程 IP 池加载超时 |
| `TG_TOKEN` | Telegram Bot Token |
| `TG_ID` | Telegram Chat ID |
| `TG_ENABLED` | 是否启用 Telegram |
| `SCHEDULED_ENABLED` | 是否启用 cron 维护 |

敏感值建议放到 Cloudflare Secret 或面板配置中。仓库中不要提交真实 Token、Zone ID、Chat ID 或 KV Namespace ID。

## 检测模式

### `external-api`

`CHECK_API` 是检测接口模板，可以包含 `{proxyip}`。主接口异常时按同样规则尝试 `CHECK_API_BACKUP`。

### `cmliu-check`

`CHECK_API` 和 `CHECK_API_BACKUP` 填 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) 的 Worker 根地址，程序会请求：

```text
/check?proxyip={proxyip}
```

### `socket`

Worker 通过 `cloudflare:sockets` 直连候选地址，并使用配置的 IPv4 / IPv6 探针验证出口。任一探针成功为 `alive`；只有两族都明确拒绝连接才为 `dead`，其他异常保持 `unknown`。

## HTTP API

除 `/api/health` 外，业务接口统一鉴权。配置 `AUTH_KEY` 后可使用：

```http
Authorization: Bearer <key>
```

或：

```text
?key=<key>
```

主要接口：

```text
GET    /api/health
GET    /api/check?proxyip=1.2.3.4:443
POST   /api/check
POST   /api/check/batch
GET    /api/pools
POST   /api/pools
PUT    /api/pools/order
GET    /api/pools/:key
PUT    /api/pools/:key
PATCH  /api/pools/:key
DELETE /api/pools/:key
POST   /api/pools/trash/restore
POST   /api/pools/trash/clear
GET    /api/domain-bindings
PUT    /api/domain-bindings
GET    /api/config
PUT    /api/config
POST   /api/config/probe/test
POST   /api/maintenance/run
POST   /api/remote-load
```

只有这一套 `/api/*`。

## KV 数据

| Key | 内容 |
| --- | --- |
| `app_config` | 面板配置、域名区域、维护目标与运行时参数 |
| `ip_pool_default` | 默认 IP 池 |
| `ip_pool_001`、`ip_pool_002` 等 | 自定义 IP 池 |
| `ip_pool_trash` | 垃圾桶 |
| `domain_pool_mapping` | 域名与 IP 池绑定 |
| `domain_pool_order` | 域名显示顺序 |
| `ip_pool_names` | 池 ID 与显示名称 |
| `ip_pool_order` | 池显示顺序 |

IP 池标准格式：

```text
ip:port,asn,country,stack # 可选备注
```

示例：

```text
192.0.2.10:443,AS64500,JP,v4
[2001:db8::1]:443,AS64501,US,v6
198.51.100.20:443,AS64500/AS64501,JP/US,v4/v6
```

旧的两字段、三字段和备注格式仍可直接读取，不需要迁移。更新检测结果时不会用 `null` 或 `unknown` 覆盖已经存在的有效 ASN、国家和出口栈。

## 开发

要求 Node.js 22。

```powershell
cd app
npm ci
npm run typecheck
npm run test
npm run build
npm run check:size
```

完整门禁：

```powershell
npm run check
```

`npm run build` 会：

1. 构建 `app/web/`；
2. 把前端产物打包进 Worker；
3. 生成仓库根目录 `worker.js`；
4. 保留本地副本 `app/dist/release/worker.js`。

`worker.js` 是生成文件，不要直接手工修改。源码始终以 `app/` 为准。

架构：

```text
app/
├─ src/
│  ├─ contracts/      跨层类型与轻量校验
│  ├─ domain/         纯业务规则
│  ├─ application/    用例编排
│  ├─ ports/          存储、探针、DNS、通知接口
│  ├─ adapters/       KV、探针、DNS、Telegram、打包资源
│  ├─ transport/      HTTP 路由、鉴权与错误映射
│  ├─ jobs/           cron 与手动维护
│  ├─ config/         环境变量与运行时装配
│  └─ worker.ts       唯一 Worker 装配入口
├─ web/               Preact + Vite 前端
└─ scripts/           构建、清理、体积门禁与 UI 审计
```

## 参考

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)

## License

[MIT](./LICENSE)