# DDNS Pro

部署在 Cloudflare Workers 上的 ProxyIP 管理面板，通过外部检测 API 验证节点，自动维护 Cloudflare DNS，无需自建服务器。

- **DNS 维护**：支持多个域名、`A/AAAA` 和 `TXT` 记录，按国家、ASN、IPv4/IPv6 筛选并补充可用节点。
- **IP 池管理**：导入、检测、去重、自定义池、域名绑定和垃圾桶恢复。
- **定时任务与通知**：每 3 小时维护一次，可在面板关闭；支持 Telegram 报告。

## 部署

### 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/231128ikun/DDNS-cf-proxyip/tree/main/app)

按 [Cloudflare 向导](https://developers.cloudflare.com/workers/platform/deploy-buttons/)授权账号，确认新仓库、Worker 与 KV，并填写一次长随机面板密钥 `AUTH_KEY`。**检测 API 无需填写**，首次启动直接使用内置备用接口；构建命令、Node.js 22 和资源绑定均已提供。

官方按钮会在你账号下创建新仓库，将 `app/` 作为仓库根目录。已有仓库或 Worker 使用下方 Git 构建与更新步骤，不需要再建仓库。密钥需要在向导设置一次，不能使用公开模板中的共用密钥。

**已有实例不要重新创建空 KV**，请按下方更新步骤保留原数据。

### Git 构建

在 Cloudflare Workers Builds 中连接仓库：

| 设置项 | 完整仓库 | 一键部署生成的仓库 |
| --- | --- | --- |
| 根目录 | `app` | 仓库根目录 |
| 构建命令 | `npm run build` | `npm run build` |
| 部署命令 | `npm run deploy` | `npm run deploy` |

Node.js 版本由 `.node-version` 选择。若平台未自动安装依赖，构建命令改为 `npm ci && npm run build`。Worker 名称须与 `wrangler.toml` 一致，默认为 `ddns-cf-proxyip`。

`npm run deploy` 会先执行完整验证，不要替换成裸 `wrangler deploy`。Worker 与静态面板一起发布，不需要另建 Pages 项目。

### 本地部署

安装 Node.js 22.12+（22 LTS）或 24 LTS，在完整仓库的 `app/` 目录执行；一键部署生成的仓库则在根目录执行：

```sh
npm ci
npx wrangler login
npx wrangler secret put AUTH_KEY
npm run deploy
```

KV 绑定名固定为 `IP_DATA`。新实例按提示创建；更新同名 Worker 时保留已有绑定。若需在 `wrangler.toml` 显式填写 Namespace ID，仅在本地或受控部署环境设置，不提交真实资源标识。

### 更新已有实例

1. 保留原 Worker、域名/路由、Secrets 和 `IP_DATA` 对应的 KV；无需转换或清空数据。
2. 按上表检查根目录与构建命令，再通过原 Git 构建或本地部署更新。
3. 更新前备份 KV 并保留可回退版本；代码回退不会恢复 KV 或 DNS。更新后先确认登录、配置和 IP 池，再执行维护。

若日志提示 `No dependencies detected` 或静态资源目录不存在，检查根目录及构建命令。GitHub Actions 负责验证，Cloudflare Workers Builds 负责部署。

## 配置

首次登录后，在**配置中心**填写并保存：

1. **Cloudflare 授权**：使用 [API Token](https://dash.cloudflare.com/profile/api-tokens) 的 **Edit zone DNS** 模板，授权需要维护的域名；Zone ID 在该域名概览页获取。
2. **管理域名**：设置前缀、记录类型、端口、最小活跃数和出口筛选条件。
3. **检测接口（可选）**：默认内置接口可直接工作；需要自建时可使用 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)，填写 `https://probe.example.com/check?proxyip=`，也支持 `{proxyip}` 占位符。备用接口可选。
4. **通知与任务**：按需填写 Telegram 配置、启用通知和自动维护。

**公开地址前务必设置 `AUTH_KEY`；为空时不启用鉴权。** Token 与 Zone ID 必须对应目标 DNS，Worker 可以部署在另一账号。不要提交密钥、个人资源 ID 或数据备份。

配置保存到 KV 的 `app_config`，优先于环境变量；环境变量仅用于启动默认值和配置故障回退。

<details>
<summary>环境变量（通常直接在面板配置即可）</summary>

| 变量 | 用途 |
| --- | --- |
| `AUTH_KEY` | 面板访问密钥 |
| `CF_KEY`、`CF_ZONEID`、`CF_BASE_DOMAIN` | Cloudflare Token、Zone ID、托管域名 |
| `CHECK_API`、`CHECK_API_BACKUP` | 可选主、备用接口；未设置时使用内置备用接口 |
| `DOH_API` | DNS 查询接口，默认 `https://cloudflare-dns.com/dns-query` |
| `CONCURRENT_CHECKS` | 检测并发数，默认 32，范围 1–128 |
| `CHECK_TIMEOUT`、`REMOTE_LOAD_TIMEOUT`、`DOH_TIMEOUT` | 检测、远程加载与 DNS 查询超时，单位毫秒 |
| `TG_TOKEN`、`TG_ID` | Telegram Bot Token、Chat ID |
| `TG_ENABLED`、`SCHEDULED_ENABLED` | 通知与定时维护开关，默认 `true` |

在面板显式清空并保存检测接口会禁用该接口；旧配置缺失字段时沿用启动默认值。公共检测服务不保证长期可用，建议自行部署。

</details>

## 使用

1. **导入**：粘贴地址、Excel 的 IP/端口两列，或加载远程 TXT 链接。
2. **检测并入库**：选择 IP 池，检测后保存；批量检测中断可继续，放弃时保留已完成结果。
3. **绑定并维护**：将管理域名绑定到池，点击“执行维护”；后续由定时任务检测并补充节点。

IP 池支持纯地址和带元数据的格式；IPv6 带端口须使用方括号：

```text
192.0.2.10:443
[2001:db8::1]:443
192.0.2.20:443,AS64500,JP,v4 # 可选备注
```

标准格式为 `ip:port,asn,country,stack`，未知字段用 `null`，`stack` 为 `v4`、`v6` 或 `v4/v6`。旧的两字段、三字段与备注格式仍可读取。

域名探测支持 `example.com`（解析 A/AAAA 后检测）、`txt@example.com`（读取 TXT 地址列表）和 `example.com:8080`（直接检测该目标）。

### 操作边界

- 检测可用时立即返回；失败或接口异常会复检。只有一个接口时复用同一接口，配置两个时依次使用主接口和备用接口。复检仍异常时保留为 `unknown`。
- **探针异常不是节点失效**：超时、HTTP、TLS/证书错误、坏 JSON 等记为 `unknown`，不据此删除 DNS 或移入垃圾桶。只有可信探针明确判定不可用时才视为失效。
- 出口国家、ASN 或栈不匹配的节点可从目标 DNS 移除，但不当作死节点入桶。`A/AAAA` 保存地址，`TXT` 在单条记录内保存地址列表。
- “从库中移除”会删除输入框列出的地址；先加载全池再执行会清空该池。
- 服务端“一键洗库”单次最多 200 个不同有效地址。超限、存在接口异常或无法识别的条目时不写回、不入桶；大池可用面板逐地址批量检测。
- 手动维护、IP 变动、库存不足或 Cloudflare 配置错误可触发 Telegram 报告。

<details>
<summary>维护与验证</summary>

在 `app/` 执行 `npm ci && npm run check`；UI 改动另运行 `npm run audit:ui`、`npm run audit:ui:regression` 与 `npm run audit:flows`（需要 Chrome/Edge 和完整 Git 历史）。

源码、测试、锁文件和构建配置保留在 GitHub；线上仅发布 Worker 与 `dist/web`。依赖、缓存、截图报告和构建产物不入库。日常在 `beta` 验证，通过 PR 与 CI 后合并到 `main`。

</details>

## 参考与许可

参考项目：[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)、[CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)、[CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)。

[MIT License](./LICENSE)
