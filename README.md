# DDNS Pro - Cloudflare Worker ProxyIP 管理面板

一个部署在 Cloudflare Workers 上的动态 DNS 与 ProxyIP 维护工具。它通过**外部 ProxyIP 检测 API** 校验节点可用性，并自动维护 Cloudflare DNS 里的 `A`、`AAAA` 或 `TXT` 记录，让目标域名尽量保持指向可用的 ProxyIP。

项目不依赖自建服务器，核心代码是单文件 Worker：[`_worker.js`](./_worker.js)。

> 本项目依赖 check-proxyip-api，若要自行部署暂无具体的开源代码，其中主要的原理见下方参考代码。

---

## 📖 项目简介

这个项目适合用于维护 Cloudflare Worker / Pages 反代场景中常见的 ProxyIP，例如让多个业务子域名持续指向可用的反代 IP。

ProxyIP 的背景说明可参考：[什么是 ProxyIP?](https://github.com/231128ikun/CF-Workers-CheckProxyIP/blob/main/README.md#-%E4%BB%80%E4%B9%88%E6%98%AF-proxyip-)


### ✨ 核心特性

- **多域名维护**：支持多个托管域名。
- **两种记录模式**：地址记录模式维护 `A/AAAA`，TXT 模式维护一条 TXT 记录里的 IP 列表。
- **自动补位**：检测失效 IP，删除不合格记录，并从 IP 池补充新 IP。
- **IP 池管理**：支持通用池、自定义池、域名绑定池和垃圾桶恢复。
- **出口筛选**：按 IPv4、IPv6、双栈、国家和 ASN 过滤候选节点。
- **Web 面板**：导入、清洗、去重、筛选、探测、维护都可以在面板完成。
- **Telegram 通知**：手动维护、IP 变化、库存不足或配置错误时可推送报告。
- **KV 配置**：配置中心会把运行配置保存到 Cloudflare KV，覆盖环境变量默认值。

### 页面展示
<details>
<summary>点击展开</summary>

![配置中心](./img/config-center.jpg)

![运行面板](./img/dashboard.jpg)

</details>

---

## 💡 快速部署

> [!TIP]
> 推荐部署顺序：复制 Worker 代码 -> 绑定 KV -> 可选设置 `AUTH_KEY` -> 打开面板 -> 配置中心保存配置。

### ⚙️ Workers 部署

<details>
<summary><code><strong>「 Workers 部署文字教程 」</strong></code></summary>

1. 部署 CF Worker：
   - 进入 [Cloudflare Workers](https://dash.cloudflare.com/?to=/:account/workers)。
   - 创建一个 Worker。
   - 把 [`_worker.js`](./_worker.js) 的全部内容复制到 Worker 编辑器。
   - 保存并部署。

2. 绑定 KV 命名空间：
   - 在 [Workers KV](https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces) 创建命名空间，名称可用 `IP_DATA`。
   - 打开 Worker -> **Settings** -> **Bindings**。
   - 添加 **KV Namespace** 绑定。
   - `Variable name` 必须填写 `IP_DATA`。

   ```text
   IP_DATA
   ```

   未绑定 `IP_DATA` 时，面板可以打开，但配置保存、IP 池和维护任务不可用。

3. 可选设置面板访问密钥：
   - 建议设置 `AUTH_KEY`，否则公开 Worker 地址后任何人都可以进入管理面板。
   - 在 Worker -> **Settings** -> **Variables** 添加变量：

   | 变量名 | 必填 | 说明 |
   | --- | --- | --- |
   | `AUTH_KEY` | 可选 | 管理面板访问密钥 |

   首次访问时，可以直接在页面中输入 `AUTH_KEY` 的值，也可以访问：

   ```text
   https://你的-worker-url/?key=你的AUTH_KEY
   ```

   登录后 Worker 会写入 HttpOnly Cookie，后续可直接打开面板。

4. 打开面板并进入配置中心：
   - 打开 Worker 地址。
   - 进入 **配置中心**。
   - 填写维护域名、Zone ID、CF Key、管理域名、检测 API、Telegram 等配置。
   - 保存后配置会写入 KV 的 `app_config`，优先级高于环境变量。

</details>

### ⏱️ 定时任务配置

<details>
<summary><code><strong>「 Cron Triggers 配置 」</strong></code></summary>

如需自动维护，需要同时开启配置中心里的自动维护开关，并在 Worker 中配置 Cron Triggers。只开启自动维护开关但没有配置定时任务时，自动维护不会触发。

Worker -> **Triggers** -> **Cron Triggers** 添加，例如：

```text
0 */3 * * *
```

表示每 3 小时执行一次自动维护。

</details>

---

## 🔑 配置说明

### Cloudflare API Token 与 Zone ID

<details>
<summary><code><strong>「 Token 与 Zone ID 获取方式 」</strong></code></summary>

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2. 打开 **My Profile** -> **API Tokens**。
3. 使用 **Edit zone DNS** 模板创建 Token。
4. Zone Resources 选择需要维护 DNS 的域名。
5. 保存 Token。Cloudflare 只会完整显示一次。

同时在域名概览页复制对应`域名`的 **Zone ID**（**区域ID**）。

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
| `AUTH_KEY` | 面板访问密钥 | 空 |
| `CF_KEY` | Cloudflare API Token | 空 |
| `CF_ZONEID` | Cloudflare Zone ID | 空 |
| `CF_BASE_DOMAIN` | 托管域名，例如 `example.com` | 空 |
| `CHECK_API` | 主 ProxyIP 检测接口 | `https://api.090227.xyz/check?proxyip=` |
| `CHECK_API_BACKUP` | 备用检测接口 | 空 |
| `DOH_API` | DNS over HTTPS 接口 | `https://cloudflare-dns.com/dns-query` |
| `TG_TOKEN` | Telegram Bot Token | 空 |
| `TG_ID` | Telegram Chat ID | 空 |
| `TG_ENABLED` | Telegram 通知开关 | `true` |
| `SCHEDULED_ENABLED` | 定时维护开关 | `true` |

### 配置中心填写项

| 配置区域 | 主要内容 |
| --- | --- |
| 维护域名配置 | 维护的域名、Zone ID、CF Key。 |
| 管理域名 | 前缀、记录类型、端口、最小活跃数。 |
| 出口筛选 | IPv4、IPv6、双栈、国家、ASN。 |
| 检测接口 | 主检测 API、备用检测 API。 |
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
   - 或输入一个 `http://` / `https://` 的 TXT 地址，从远程 URL 加载。
   - 点击 **检测** 验证可用性并规范格式。
   - 点击 **入库** 保存到当前 IP 池。

3. 绑定域名和 IP 池：
   - 将需要维护的管理域名绑定到对应 IP 池。
   - 可以使用默认池，也可以使用自定义池。

4. 执行维护：
   - 点击 **执行维护**。
   - Worker 会检测当前 DNS 记录，删除失效或不匹配筛选条件的记录，并从绑定的 IP 池中补充可用 IP。

> 点击从**库中移除**则从库中移除输入框中的数据。比如想清空 ip 库，可以从库中加载所有的 ip 至输入框，点击从库中移除则库中所有的 ip 就都清空了。

域名探测输入框中可以输入：

```text
example.com
example.com:8080
txt@example.com
1.2.3.4:443
[2606:4700::1]:443
```

</details>

---

## 🧩 内部设计说明

下面内容主要用于了解项目内部数据格式、检测接口要求和维护流程。普通部署只需要看前面的快速部署、配置说明和使用说明。

### 检测 API

<details>
<summary><code><strong>「 检测 API 返回字段 」</strong></code></summary>

检测接口支持两种形式：

```text
https://example.com/check?proxyip=
https://example.com/check?proxyip={proxyip}
```

使用 `{proxyip}` 时，Worker 会替换占位符；否则会把编码后的地址直接拼到 URL 末尾。

Worker 会以 `GET` 请求调用检测接口，请求地址中的 `proxyip` 值为待检测地址，例如 `1.2.3.4:443` 或 `[2606:4700::1]:443`。接口需要返回 JSON 对象；HTTP 非 2xx、非 JSON 或超时都会视为本次检测失败，并在配置了备用检测接口时继续复检。

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
| `ip_pool_names` | IP 池显示名称，JSON 对象，key 为池 ID，value 为显示名 |

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
