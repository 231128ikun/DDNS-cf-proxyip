# DDNS Pro - Cloudflare Worker ProxyIP 管理面板


一个部署在 Cloudflare Workers 上的 ProxyIP 维护工具。它通过**外部 ProxyIP 检测 API** 校验节点可用性，并自动维护 Cloudflare DNS 里的 `A`、`AAAA` 或 `TXT` 记录，让目标域名尽量保持指向可用的 ProxyIP。

项目不依赖自建服务器。`app/` 是唯一源码入口：Worker 处理 `/api/*`，浏览器端由 Cloudflare 静态资源分发，仓库不提交构建产物。

> 本项目依赖 check-proxyip-api，若要自行部署后端代码，见下方参考代码。现在可行的方案是部署[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)然后将` http://部署的项目地址/check?proxyip= `填入检测api中。（snippets版本可参考[CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)自行修改）

---

## 📖 项目简介

这个项目适合用于维护 Cloudflare Worker / Pages 反代场景中常见的 ProxyIP，例如让多个业务子域名持续指向可用的反代 IP。

ProxyIP 的背景说明可参考：[什么是 ProxyIP?](https://github.com/231128ikun/CF-Workers-CheckProxyIP/blob/main/README.md#-%E4%BB%80%E4%B9%88%E6%98%AF-proxyip-)


### ✨ 核心特性

- **多域名维护**：支持添加多个cf托管域名。
- **两种记录模式**：地址记录模式维护 `A/AAAA`，TXT 模式维护一条 TXT 记录里的 IP 列表。
- **自动补位**：检测失效 IP，删除不合格记录，并从 IP 池补充新 IP。
- **IP 池管理**：支持通用池、自定义池、域名绑定池、池列表自定义排序和垃圾桶恢复。
- **出口筛选**：按 IPv4、IPv6、双栈、国家和 ASN 过滤候选节点。
- **Web 面板**：导入、清洗、去重、筛选、探测、维护都可以在面板完成。
- **Telegram 通知**：手动维护、IP 变化、库存不足或配置错误时可推送报告。
- **KV 配置**：配置中心会把运行配置保存到 Cloudflare KV，覆盖环境变量默认值。

---

## 合并前的部署切换

合并与部署均需单独确认。若 main 已接入自动部署，合并前先核实构建设置，避免合并立即覆盖现有服务。保留原 Worker 名称 `ddns-cf-proxyip`、域名路由和原 `IP_DATA` 绑定；入口改为 `app/src/index.ts`，静态资源为 `app/dist/web`。旧单文件复制和旧文件同步发布流程不再适用。切换前保留部署版本及受控 KV 备份；代码回退不会恢复 KV 或 DNS。

## 💡 快速部署

> [!TIP]
> 推荐部署顺序：准备 Node.js 22 -> 构建源码 -> 绑定 KV -> 部署 -> 打开面板保存配置。
> 仓库不再提供“复制单文件到 Worker 编辑器”的部署方式，也不提交 `_worker.js`。

### ☁️ Cloudflare 构建设置

| 设置项 | 值 |
| --- | --- |
| Build command | `cd app && npm ci` |
| Deploy command | `cd app && npm run deploy` |

- Worker 名称、入口和静态资源目录都由仓库根目录的 [`wrangler.toml`](./wrangler.toml) 决定：入口是 `app/src/index.ts`，静态资源目录是 `app/dist/web`。
- `npm run deploy` 会先执行 `npm run check`；类型检查、接口契约、单测、构建、体积门禁或部署形态冒烟任一失败时，不会发布。
- 部署前确认 `IP_DATA` 绑定到原有 KV Namespace，避免重新创建空库；资源标识仅在部署环境配置，不提交仓库。
- 部署完成后打开 Worker 地址，在 **配置中心** 填写 Zone ID、CF Key、维护域名与检测 API。
- 建议设置 `AUTH_KEY` 或在配置中心填写“面板密钥”。开启后，静态前端只会渲染登录卡片，`/api/*` 统一拒绝未认证请求；支持 `?key=`、Bearer、`X-Auth-Key` 和 HttpOnly Cookie。

### ⚙️ Wrangler 本地部署

<details>
<summary><code><strong>「 Wrangler 部署文字教程 」</strong></code></summary>

1. 准备环境：
   - Node.js 22 或更新版本。
   - 已登录 Cloudflare 的 Wrangler CLI。

   ```powershell
   npx wrangler login
   ```

2. 构建 Worker 与前端静态资源：

   ```powershell
   cd app
   npm ci
   npm run build
   ```

   构建结果是：

   - `app/dist/web/`：面板静态资源，由 `wrangler.toml` 的 `[assets]` 声明；
   - `app/dist/release/worker.js`：Wrangler 打包检查产物，只用于体积门禁，不是仓库入口。

3. 绑定 KV 命名空间：
   - 创建或选择一个 KV Namespace。
   - 在 `wrangler.toml` 的 `[[kv_namespaces]]` 里把 `IP_DATA` 绑定到该 Namespace，已有 Namespace 时需要填写其 `id`。

   ```toml
   [[kv_namespaces]]
   binding = "IP_DATA"
   id = "你的_KV_Namespace_ID"
   ```

   未绑定 `IP_DATA` 时，面板可以打开，但配置保存、IP 池和维护任务不可用。

4. 部署：

   ```powershell
   npm run deploy
   ```

5. 打开面板并进入配置中心：
   - 打开 Worker 地址。
   - 进入 **配置中心**。
   - 填写维护域名、Zone ID、CF Key、管理域名、检测 API、Telegram 等配置。
   - 保存后配置会写入 KV 的 `app_config`，优先级高于环境变量。

7. 定时维护：
   - `wrangler.toml` 已声明每 3 小时一次的 Cron：

   ```text
   0 */3 * * *
   ```

   - 同时需要在配置中心开启自动维护；关闭时定时任务会直接跳过。

</details>

### 🚀 Cloudflare Git 集成部署

<details>
<summary><code><strong>「 Git 集成部署文字教程 」</strong></code></summary>

1. 在 Cloudflare Workers 中连接本仓库。
2. 确认合并获批后，生产分支选择 `main`；Worker 项目名称需与 `wrangler.toml` 里的 `name` 一致，即 `ddns-cf-proxyip`。
3. 在构建配置中填写：

   ```text
   Build command: cd app && npm ci
   Deploy command: cd app && npm run deploy
   ```

4. 为 Worker 绑定 KV，变量名必须是 `IP_DATA`。
5. 打开面板完成配置。

> [`wrangler.toml`](./wrangler.toml) 是部署事实源：Worker 入口是 `app/src/index.ts`，静态资源目录是 `app/dist/web`，KV 绑定名是 `IP_DATA`，并声明每 3 小时一次的 Cron。

</details>
## 🔑 配置说明

### Cloudflare API Token 与 Zone ID

<details>
<summary><code><strong>「 Token 与 Zone ID 获取方式 」</strong></code></summary>

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2. 打开 **My Profile** -> **API Tokens**。
3. 使用 **Edit zone DNS** 模板创建 Token。
4. Zone Resources 选择需要维护 DNS 的域名。
5. 保存 Token。Cloudflare 只会完整显示一次。

同时在域名概览页点击右侧三个点，复制对应`域名`的 **Zone ID**（**区域ID**）。

> API Token 和 Zone ID 是你要维护的域名的 Cloudflare 账号中的。而这个项目可以部署在任意 Cloudflare 账号下。

</details>

### 必需绑定

| 类型 | 名称 | 说明 |
| --- | --- | --- |
| KV Namespace Binding | `IP_DATA` | 保存运行配置、IP 池、垃圾桶和域名池绑定 |

### 可选环境变量

这些变量只作为初始默认值。上线后更推荐在面板的配置中心维护，保存后写入 KV。

| 变量名 | 说明 | 默认值 |
| --- | --- | --- |
| `CF_KEY` | Cloudflare API Token | 空 |
| `CF_ZONEID` | Cloudflare Zone ID | 空 |
| `CF_BASE_DOMAIN` | 托管域名，例如 `example.com` | 空 |
| `AUTH_KEY` | 面板访问密钥；为空时关闭面板鉴权 | 空 |
| `CHECK_API` | 主 ProxyIP 检测接口 | 空 |
| `CHECK_API_BACKUP` | 备用检测接口 | `https://checkapi.dvb.kdns.fr/?candidate=` |
| `DOH_API` | 公共 DNS 查询接口，`txt@域名` 与域名解析探测使用 | `https://cloudflare-dns.com/dns-query` |
| `CONCURRENT_CHECKS` | 浏览器批量与当前记录检测并发，范围 1–128 | `32` |
| `DOH_TIMEOUT` | DoH 查询超时（毫秒），范围 1000–30000 | `5000` |
| `TG_TOKEN` | Telegram Bot Token | 空 |
| `TG_ID` | Telegram Chat ID | 空 |
| `TG_ENABLED` | Telegram 通知开关 | `true` |
| `SCHEDULED_ENABLED` | 定时维护开关 | `true` |

> 公共备用检测 API 不保证长期可用，建议自行部署。批量清洗在首轮检测进行期间，失败项或接口异常项会立即在当前检测槽位内复检，不等待所有首轮项目结束；单项探测和维护仍在同一个检测任务内依次尝试主、备用接口。配置中心显式清空并保存主/备用接口后，该接口会被禁用；旧配置中缺少的字段仍使用环境默认值。

> 批量检测沿用 main 的模型：浏览器按配置的 `CONCURRENT_CHECKS`（默认 32）逐个地址请求 Worker，每个请求只探测一个目标；单个目标异常记为未知并继续后续检测。中断后继续只处理未完成项，放弃则保留已完成的清洗结果。配置与保存仍使用原有 `app_config.settings`。

### 配置中心填写项

| 配置区域 | 主要内容 |
| --- | --- |
| 维护域名配置 | 维护的域名、Zone ID、CF Key。 |
| 管理域名 | 前缀、记录类型、端口、最小活跃数。 |
| 出口筛选 | IPv4、IPv6、双栈、国家、ASN。 |
| 检测接口 | 主检测 API、备用检测 API、DoH 查询接口。 |
| 访问控制 | 面板密钥 `AUTH_KEY`；为空时关闭鉴权。 |
| 通知与任务 | Telegram 配置、Telegram 通知开关、定时维护开关。 |

---

## 🧭 使用说明

### 面板使用流程

<details>
<summary><code><strong>「 从配置到维护 」</strong></code></summary>

1. 确认 **管理域名** 板块已经配置完成：
   - 在 **配置中心** 中填写需要维护的管理域名。
   - 确认前缀、记录类型、端口、最小活跃数、出口筛选等配置符合预期。
   - 保存配置到 KV。

2. 导入 IP 并入库：
   - 在 **手动输入** 中粘贴 IP 列表。

   ```text
   1.2.3.4:443
   5.6.7.8:8080
   [2606:4700::1]:443
   ```

   - 也可以从 Excel 复制 `IP地址` 和 `端口` 两列后直接粘贴。
   - 或输入一个 远程 TXT链接 ，从远程 URL 加载。
   - 点击 **检测** 验证可用性并规范格式。
   - 点击 **入库** 保存到当前 IP 池。

3. 绑定域名和 IP 池：
   - 将需要维护的管理域名绑定到对应 IP 池。
   - 可以使用默认池，也可以使用自定义池。
   - IP 池较多时，点击池选择器旁的 **↕️** 按钮，可用上移/下移调整自定义池顺序并保存。默认池固定在最前，垃圾桶固定在最后。
   - 配置中心的权限配置和管理域名卡片支持点击展开编辑，再次点击当前卡片可收起编辑面板。
   - 域名池绑定区域也可以点击 **↕️** 按钮调整管理域名的显示顺序；该排序只影响绑定表展示，不改变维护执行顺序。

4. 执行维护：
   - 点击 **执行维护**。
   - Worker 会检测当前 DNS 记录，删除失效或不匹配筛选条件的记录，并从绑定的 IP 池中补充可用 IP。

> 点击从**库中移除**则从库中移除输入框中的数据。比如想清空 ip 库，可以从库中加载所有的 ip 至输入框，点击从库中移除则库中所有的 ip 就都清空了。

域名探测输入框中可以输入：

```text
example.com          # 先解析 A/AAAA，再逐个探测解析结果
example.com:8080     # 带端口的输入按字面目标探测
txt@example.com      # 读取 TXT 记录里的地址列表并逐个探测
1.2.3.4:443
[2606:4700::1]:443
```

解析失败只会提示错误，不会把节点标记为失效；TXT 记录里的地址沿用同一个池格式（`ip:port,asn,country,stack`），无端口时按 443 处理。

</details>

---

## 🧩 内部设计说明

下面内容主要用于了解项目内部数据格式、检测接口要求和维护流程。普通部署只需要看前面的快速部署、配置说明和使用说明。

### 仓库结构

| 路径 | 用途 |
| --- | --- |
| `app/src/contracts/` | 跨层类型、API 输入输出与轻量手写校验 |
| `app/src/domain/` | 地址、目标、探针结果、IP 池等纯业务规则 |
| `app/src/application/` | 用例编排；不直接访问 `env`、KV 或 `fetch` |
| `app/src/ports/` | 存储、探针、DNS、通知等接口 |
| `app/src/adapters/` | KV、Cloudflare DNS、探针、DoH、Telegram 等外部实现 |
| `app/src/transport/` | HTTP 路由、鉴权、请求校验和错误映射 |
| `app/src/jobs/` | cron 与手动维护共用的任务入口 |
| `app/src/config/` | 环境变量解析与运行时适配器装配 |
| `app/web/` | 浏览器端 Preact 源码（构建到 `app/dist/web`） |
| `app/scripts/` | 构建、清理、体积门禁、冒烟与 UI 验收脚本 |
| `wrangler.toml` | 部署事实源：Worker 入口、静态资源目录、KV 绑定与 Cron |

依赖方向固定为 `transport/jobs -> application -> domain + ports <- adapters`：业务规则不依赖 HTTP、KV、`fetch` 或页面。

### 检测 API

<details>
<summary><code><strong>「 检测 API 返回字段 」</strong></code></summary>

检测接口支持两种形式：

```text
https://example.com/check?proxyip=
https://example.com/check?proxyip={proxyip}
```

使用 `{proxyip}` 时，Worker 会替换占位符；否则会把编码后的地址直接拼到 URL 末尾。

Worker 会以 `GET` 请求调用检测接口，请求地址中的 `proxyip` 值为待检测地址，例如 `1.2.3.4:443` 或 `[2606:4700::1]:443`。接口需要返回可识别的检测 JSON 对象（例如含布尔值 `success`）。HTTP 非 2xx、非 JSON、空对象或不符合检测结构的 JSON 视为接口异常；超时（包括上游报告的 TCP 连接超时）仍为未知，不据此删除 DNS 或移入垃圾桶；配置备用接口时会按既有规则重试。日志会区分“未知（超时）”与“未知（HTTP 异常）”，HTTP 502 错误页不会直接展示在日志中。

代码实际消费的返回字段样式如下：

```json
{
  "success": true,
  "proxyIP": "1.2.3.4",
  "portRemote": "443",
  "responseTime": 123,
  "colo": "HKG",
  "inferred_stack": "v4/v6",
  "exits": [
    {
      "stack": "ipv4",
      "ip": "203.0.113.10",
      "colo": "HKG",
      "country": "HK",
      "city": "Hong Kong",
      "asn": 64500,
      "asOrganization": "Example Network"
    },
    {
      "stack": "ipv6",
      "ip": "2001:db8::10",
      "colo": "HKG",
      "country": "HK",
      "city": "Hong Kong",
      "asn": 64501,
      "asOrganization": "Example Network"
    }
  ]
}
```

字段说明：

| 字段 | 用途 |
| --- | --- |
| `success` | 判断节点是否可用。维护流程和检测清洗只保留可用节点。 |
| `proxyIP` | 检测清洗后写入 IP 池的地址；缺失时使用请求中的 IP。 |
| `portRemote` | 检测清洗后写入 IP 池的端口；缺失时使用请求中的端口。 |
| `responseTime` | 面板、维护日志和通知里展示的检测耗时。 |
| `colo` | 面板、维护日志和通知里展示的 Cloudflare 机房。 |
| `inferred_stack` | 节点出口类型，建议返回 `v4`、`v6` 或 `v4/v6`，用于出口筛选和 IP 池第四字段。 |
| `exits` | 出口详情列表，用于面板展示，并汇总生成 IP 池里的 `asn,country,stack`。 |

`exits` 数组对象字段：

| 字段 | 用途 |
| --- | --- |
| `stack` | 单个出口类型，例如 `ipv4` 或 `ipv6`。 |
| `ip` | 面板展示的出口 IP。 |
| `colo` | 出口机房。 |
| `country` | 面板展示、国家筛选和 IP 池第三字段。 |
| `city` | 面板出口位置展示。 |
| `asn` | 面板展示、ASN 筛选和 IP 池第二字段。 |
| `asOrganization` | 面板展示的 ASN 组织名称。 |

</details>

### KV 数据

<details>
<summary><code><strong>「 KV 数据键与 IP 池格式 」</strong></code></summary>

Worker 会使用以下 KV key：

| Key | 说明 |
| --- | --- |
| `app_config` | 面板保存的运行配置 |
| `ip_pool_default` | 默认 IP 池 |
| `ip_pool_001`、`ip_pool_002` ... | 自定义 IP 池，按三位数字递增创建 |
| `ip_pool_trash` | 垃圾桶 |
| `domain_pool_mapping` | 管理域名到 IP 池的绑定 |
| `domain_pool_order` | 域名池绑定区域中管理域名的显示顺序，JSON 数组；旧数据缺少此键时按配置中的管理域名顺序显示 |
| `ip_pool_names` | IP 池显示名称，JSON 对象，key 为池 ID，value 为显示名 |
| `ip_pool_order` | IP 池显示顺序，JSON 数组；旧数据缺少此键时自动按原编号顺序显示 |
| pool_stats_baseline | 距上次成功通知的各池数量基线，JSON 对象；只在维护通知成功发送后更新 |

IP 池的 KV key 不再使用用户输入的名称。新建池时 Worker 自动分配 `ip_pool_###`，用户看到的池名称只保存在 `ip_pool_names` 中。

检测清洗并入库后，IP 池按四字段保存：

```text
ip:port,asn,country,stack
```

示例：

```text
192.0.2.10:443,AS64500,JP,v4
[2001:db8::1]:443,AS64501,US,v6
198.51.100.20:443,AS64500/AS64501,JP/US,v4/v6
```

字段缺失时写 `null`。`stack` 取值为 `v4`、`v6` 或 `v4/v6`。旧格式 `ip:port # 注释` 和 `ip:port,asn,country` 仍可读取；新检测结果会按四字段格式写回。

</details>

### 维护流程

<details>
<summary><code><strong>「 维护流程 」</strong></code></summary>

一次维护流程大致如下：

```text
读取目标配置
  -> 读取绑定 IP 池
  -> 查询 Cloudflare DNS 当前记录
  -> 调用检测 API 校验当前 IP
  -> 删除失效或不匹配筛选条件的记录
  -> 从 IP 池挑选候选并实时检测
  -> 补充到最小活跃数
  -> 失效池条目移入垃圾桶
  -> 按条件发送 Telegram 报告
```

通知触发条件：

- 手动执行维护。
- 有 IP 新增或删除。
- 活跃 IP 数不足且无法补齐。
- Cloudflare 配置错误。

</details>

---

## 🛠 参考代码

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D)
- [CF-Workers-检测后端](https://github.com/ToiCF/CF-Workers-CheckProxyIP)

## License

[MIT](./LICENSE)
