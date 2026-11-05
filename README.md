# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

DDNS Pro 部署于 Cloudflare Workers，通过原生 TCP/TLS 检测验证 ProxyIP，外部 API 仅用于备用复检；维护域名的 `A`、`AAAA` 或 `TXT` 记录，无需自建服务器。

## ✨ 核心功能

- **多域名维护**：检测当前节点，从绑定的 IP 池补充可用地址。
- **IP 池管理**：导入、检测、去重、筛选、自定义池与垃圾桶恢复。
- **出口筛选**：支持国家、ASN、IPv4、IPv6 和双栈条件。
- **自动任务**：每 3 小时维护一次，可在配置中心关闭；支持 Telegram 通知。

## 🚀 快速部署

> 面板密码和检测接口均为可选配置。未设置密码时不启用鉴权，默认启用原生检测，失败时使用备用接口复检。

### ① 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/231128ikun/DDNS-cf-proxyip/tree/main/app)

通过 Cloudflare 部署向导创建仓库及 Worker，按提示完成账号授权和资源设置。面板密码与检测 API 无需预先填写。

此方式适用于新实例，会创建 GitHub 仓库。已有仓库或 Worker 可使用以下 GitHub 部署及迁移/更新方式。

### ② GitHub 仓库部署

<details>
<summary><strong>展开 GitHub 部署步骤</strong></summary>

1. 在 Cloudflare **Workers & Pages** 中创建或选择 Worker，连接对应的 GitHub 仓库。
2. 选择 `main` 分支，设置：

   | 设置项 | 内容 |
   | --- | --- |
   | 根目录 | `app` |
   | 构建命令 | 留空，由 Wrangler 自动构建 |
   | 部署命令 | `npm run deploy` |

3. Worker 名称应与 `app/wrangler.toml` 一致，默认为 `ddns-cf-proxyip`。KV 绑定名固定为 **`IP_DATA`**。
4. 部署完成后打开 Worker 地址，在配置中心保存域名配置。

Cloudflare 自动选择 Node.js 并安装依赖。统一部署入口自动构建面板与 Worker，检查体积后发布；完整测试由本地和 GitHub CI 执行，不进入线上发布文件。

一键部署生成的仓库以 `app/` 为根目录，根目录设置留空；完整仓库的根目录填写 `app`。

**KV 资源：**部署入口自动初始化 `IP_DATA`；创建遇到同名冲突时复用已有命名空间，已有明确绑定保持不变。

</details>

### ③ 本地命令行部署

<details>
<summary><strong>展开 Wrangler 部署步骤</strong></summary>

安装 Node.js 22.12+ 或 24 LTS，在完整仓库的 `app/` 目录执行：

```sh
npm ci
npx wrangler login
npm run deploy
```

部署使用 `npm run deploy`；在仓库根目录执行时使用 `npm --prefix app run deploy`。

</details>

<details>
<summary><strong>已有实例迁移 / 更新</strong></summary>

1. 保留原 Worker、域名、Secrets 和 `IP_DATA` 对应的 KV 命名空间。
2. Worker 名称、部署账号和环境应与原实例一致，已有 `IP_DATA` 绑定或明确资源 ID 保持不变。
3. 使用完整仓库时，将构建根目录设为 `app`，构建命令留空，部署命令设为 `npm run deploy`。未变化的有效产物会被复用。
4. 更新前备份 KV 并保留可回退版本；更新后确认配置、IP 池和域名绑定，再执行维护。

代码回退不会恢复已变更的 KV 或 DNS。

</details>

## 🔑 配置中心

部署后完成配置并保存：

1. **维护域名配置**：托管域名、Zone ID 和 Cloudflare API Token。
2. **管理域名**：子域名、记录类型、端口、最小活跃数与出口筛选。
3. **可选设置**：面板密码、Telegram 通知、出口信息接口、备用检测 API 和自动维护开关。

面板密码 `AUTH_KEY` 支持设置、修改和清空；为空时管理接口不启用鉴权。密码、Token 和实际资源 ID 不应提交到公共仓库。

<details>
<summary>可选环境变量</summary>

在 Worker 的 **Settings → Variables and Secrets** 中配置。面板密码及 API/Bot Token 建议使用 **Secret**；其他项目可使用普通变量。未设置时使用以下默认值，配置中心保存的 KV 配置优先；环境变量用于首次启动及配置异常回退。

| 变量 | 用途 | 默认值 |
| --- | --- | --- |
| `AUTH_KEY` | 可选面板登录密码；空值免登录 | 空 |
| `CF_KEY` | Cloudflare DNS API Token | 空 |
| `CF_ZONEID` | DNS 区域 ID | 空 |
| `CF_BASE_DOMAIN` | 托管域名，如 `example.com` | 空 |
| `PROBE_IPV4_URL` | IPv4 出口 JSON 接口 | `https://ipv4.090227.xyz/` |
| `PROBE_IPV6_URL` | IPv6 出口 JSON 接口 | `https://ipv6.090227.xyz/` |
| `CHECK_API_BACKUP` | 备用检测接口 | `https://checkapi.dvb.kdns.fr/?candidate=` |
| `DOH_API` | DNS over HTTPS 查询接口 | `https://cloudflare-dns.com/dns-query` |
| `CONCURRENT_CHECKS` | 检测并发，范围 1–128 | `32` |
| `CHECK_TIMEOUT` | 单次原生连接或备用请求超时，500–30000 毫秒 | `15000` |
| `REMOTE_LOAD_TIMEOUT` | 远程文本加载超时，1000–60000 毫秒 | `8000` |
| `DOH_TIMEOUT` | DNS 查询超时，1000–30000 毫秒 | `5000` |
| `TG_TOKEN` | Telegram Bot Token | 空 |
| `TG_ID` | Telegram Chat ID | 空 |
| `TG_ENABLED` | Telegram 通知开关 | `true` |
| `SCHEDULED_ENABLED` | 定时维护开关 | `true` |

出口接口通过候选地址访问，需提供有效 HTTPS 证书并返回含 `ip` 或 `ipAddress` 的 JSON，可附带 `asn`、`country` 等信息。清空某个出口接口可关闭该分支。其他运行参数通过配置中心管理。

`IP_DATA` 是 KV namespace 类型的资源绑定，不是普通文本变量。

</details>

<details>
<summary>Cloudflare Token 与 Zone ID 获取方式</summary>

- 在 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) 使用 **Edit zone DNS** 模板，授权需要维护的域名。
- 在域名概览页复制 **Zone ID（区域 ID）**。
- Token 与 Zone ID 必须对应目标 DNS；Worker 可部署于另一账号。

</details>

<details>
<summary>自建检测接口（可选）</summary>

检测服务可参考 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)。接口地址支持：

```text
https://probe.example.com/check?proxyip=
https://probe.example.com/check?proxyip={proxyip}
```

原生检测未成功时调用备用 API 一次；备用 API 留空则原生复检一次。`TCP Loop`、运行异常和备用接口的网络/HTTP/JSON 异常不作为节点失效。公共出口与备用服务不保证长期可用。

配置保存到 KV，优先于环境变量启动默认值。

</details>

## 🧭 面板使用

1. **导入与检测**：选择 IP 池，粘贴地址，或用“从池读取”“远程链接”“本地文件”载入。输入框带格式示例，筛选框旁的问号可查看筛选用法。筛选保留原文，普通检测不写库存。
2. **选择与出入库**：在“结果”页勾选所需条目，点击“保留到输入”；再“追加入库”合并去重，或确认“从库剔除”按地址和端口移除。人工剔除保留其他条目和备注，不进入垃圾桶。检测中断后可继续。
3. **绑定并维护**：在配置中心的维护域名卡片中选择 IP 池，执行维护；后续可由定时任务运行。

<details>
<summary>地址格式与域名探测</summary>

支持纯地址和带元数据、备注的格式：

```text
192.0.2.10:443
[2001:db8::1]:443
192.0.2.20:443,AS64500,JP,v4 # 可选备注
```

IPv6 带端口必须加方括号。标准池格式为 `ip:port,asn,country,stack`，`stack` 为 `v4`、`v6` 或 `v4/v6`，未知字段用 `null`；旧池格式仍可读取。

“解析实况”读取并检测当前 DNS 地址，同时支持输入 `example.com`、`txt@example.com` 或 `example.com:8080` 进行探测。

</details>

### 操作提醒

- **失败与未知**：候选连接、TLS、目标 HTTP、出口 JSON 失败或候选超时，复检仍失败时按失效处理，洗库和维护可移入垃圾桶；检测运行异常、备用 API 自身的网络、非 2xx、坏响应或显式异常仍为未知。普通检测和解析实况刷新不改库，出口筛选不匹配也不当作死节点。
- 面板不提供整库文本编辑和覆盖。保存后使用回执更新页面；刷新图标只更新池列表和计数，“从池读取”才读取所选池的内容。写入失败不自动重试。KV 不提供多页面并发编辑的事务保障。
- 国家与地区显示探针已有的出口归属信息，优先显示城市，缺少时回退到地区；不额外查询定位服务。控制台显示当前检测请求执行的 Worker 机房，解析结果的 COLO 则是出口探针返回的机房，两者含义不同。
- “一键洗库”复用普通批检：浏览器按配置并发，每个地址单独请求，逐条显示进度。全部确认后只提交一次清理；服务端核对完整报告和库存快照，不重复探测。遇到未知结果、无效内容或库存变化时保留原池。
- 控制台框内常显运行配置，批量检测逐条输出，维护结果也在此保留；查看历史时不会强制滚到底部。机房旁圆点表示检测请求状态，节点失效不等于接口异常。
- 原生检测显式发送 SNI 并校验证书链，使用 TLS 1.3；信任库来自 Mozilla CA 数据（curl.se），在当前运行实例内缓存一天，加载失败报告检测异常。默认出口探针无需配置，自定义覆盖收纳在高级设置中。
- 鼠标悬停版本号、键盘聚焦或点击版本号可查看更新记录，记录来源为 [CHANGELOG.md](./CHANGELOG.md)。

## 参考与许可

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)
- [CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)
- [subtls](https://github.com/jawj/subtls)（MIT，显式 SNI 与 TLS 1.3 证书校验）

[MIT License](./LICENSE)
