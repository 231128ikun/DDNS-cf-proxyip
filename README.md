# DDNS Pro - Cloudflare Workers 动态DNS & IP管理

基于cmliu 的check proxyip项目提供的api做的多域名动态DNS管理系统，支持A记录、TXT记录和双模式，自动检测并替换失效IP。借助cf平台，无需服务器。

## 📋 主要功能

- ✅ **多域名管理** - 支持同时管理多个域名的DNS记录
- ✅ **三种模式** - A记录、TXT记录、双模式（ALL）
- ✅ **自动维护** - 定时检测失效IP并自动补充
- ✅ **批量检测** - 并发检测IP可用性，提高效率
- ✅ **追加入库** - 新IP追加到库存，不覆盖现有数据
- ✅ **Telegram通知** - 维护完成后推送详细报告
- ✅ **Web管理界面** - 直观的可视化操作面板

> 主要就是为了维护一个任意端口的proxyip域名用于访问cf类网站，达到的效果就是定时监控自动维护来保证域名中的ip始终可用。比如kr.dwb.cc.cd:50001

### 🎯 新手入门指南

如果你是第一次接触动态DNS，这里有一个快速理解：

1. **这是什么？** - 一个自动管理域名IP地址的工具，让你的域名始终指向可用的IP地址
2. **有什么用？** - 比如你有域名 `example.com:8080`，这个工具会：
   - 自动检查域名当前的IP是否可用
   - 如果不可用，自动从你的IP库存中挑选新的可用IP
   - 更新域名解析，让域名始终指向可用的IP
3. **三种模式选择建议**：
   - **A记录模式**：最常用，将IP直接解析到域名（如 `example.com:443`）
   - **TXT记录模式**：将IP列表存储在TXT记录中，适合需要IP列表的场景
   - **双模式**：同时维护A记录和TXT记录


<details>
<summary><strong>🚀 快速开始指南（点击展开）</strong></summary>

### 📊 完整部署流程图

```
1. 准备工作 → 2. 部署Worker → 3. 配置环境 → 4. 添加IP → 5. 开始使用
   ↓                ↓                ↓            ↓          ↓
获取API Token     复制代码       设置环境变量   导入IP库   访问管理面板
获取Zone ID       部署到CF     配置KV绑定     检测清洗    执行维护
```

## 1️⃣ 准备工作

### 获取 Cloudflare API Token

**什么是API Token？** - 这是Cloudflare给你的一串密码，用来安全地管理你的域名DNS记录。

**详细步骤：**
1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 点击右上角头像 → **My Profile**
3. 左侧菜单 **API Tokens** → **Create Token**
4. 选择 **Edit zone DNS** 模板
5. 配置权限：
   - **Zone Resources**: 选择你的域名
   - **Permissions**: Zone - DNS - Edit
   - **Permissions**: Zone - DNS - Read
6. 点击 **Continue to summary** → **Create Token**
7. **复制保存** 生成的 Token（只显示一次）

**⚠️ 重要提醒：**
- 这个Token只显示一次，请立即保存到安全的地方
- Token权限足够管理DNS即可，不需要其他权限

### 获取 Zone ID

**什么是Zone ID？** - 这是你的域名在Cloudflare系统中的唯一标识符。

**获取步骤：**
1. 在 [Cloudflare Dashboard](https://dash.cloudflare.com/) 中选择你的域名
2. 右侧 **API** 区域可以看到 **Zone ID**
3. 复制保存


## 2️⃣ 部署 Worker

### 通过 Cloudflare Dashboard

1. 访问 [Cloudflare Workers](https://dash.cloudflare.com/?to=/:account/workers)
2. 点击 **Create Application** → **Create Worker**
3. 复制 `worker.js` 的全部内容
4. 粘贴到编辑器 → **Save and Deploy**
5. 配置环境变量和KV绑定（见下方）

#### 配置环境变量

进入 Worker → **Settings** → **Variables**，添加：

```
CF_MAIL = your-email@example.com
CF_KEY = your-cloudflare-api-token
CF_ZONEID = your-zone-id
CF_DOMAIN = ddns.example.com:port&3 （前缀不填默认维护a记录，端口不填默认443，最小活跃数不填默认为3）
```

#### 创建 KV 绑定

1. 在 [KV](https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces) 创建命名空间
2. 名称：`IP_DATA`
3. 回到 Worker → **Settings** → **Bindings**
4. 点击 **Add binding**
   - Type: **KV Namespace**
   - Variable name: `IP_DATA`
   - KV namespace: 选择刚创建的命名空间

#### 配置定时任务

Worker → **Triggers** → **Cron Triggers** → **Add Cron Trigger**

```
0 */3 * * *  # 每3小时执行一次
```

## 3️⃣ 使用管理面板

访问你的 Worker 地址：
```
https://ddns-pro.你的子域名.workers.dev
```

### 第一次使用

#### Step 1: 添加IP到库存

1. 在 **手动输入** 标签页输入IP列表：
```
1.2.3.4:443
5.6.7.8:8080
```

2. 点击 **检测清洗**（自动验证IP可用性）

3. 点击 **追加入库**（保存到库存）

#### Step 2: 查看解析状态

1. 选择要管理的域名（顶部下拉框）
2. 点击 **刷新** 查看当前DNS记录

#### Step 3: 执行维护

点击 **执行全部维护** 按钮，系统会：
- 检测现有DNS记录
- 删除失效IP
- 若低于最小活跃数，则从库存补充新IP
- 发送Telegram通知（如已配置）

## 4️⃣ 配置自动维护（可选）

### 设置定时任务

在 `Worker → Triggers → Cron Triggers` 中：
```
[triggers]
crons = ["0 */3 * * *"]  # 每3小时更新
```

### 配置 Telegram 通知

1. 创建 Telegram Bot:
   - 与 [@BotFather](https://t.me/botfather) 对话
   - 发送 `/newbot` 并按提示操作
   - 获得 Token: `123456789:ABCdef...`

2. 获取 Chat ID:
   - 与 [@userinfobot](https://t.me/userinfobot) 对话
   - 发送任意消息
   - 获得 ID: `123456789`

3. 在 `环境变量` 中添加：
```
TG_TOKEN = "your-bot-token"
TG_ID = "your-chat-id"
```

4. 重新部署

## 5️⃣ 日常使用

### 批量导入IP（从Excel）

1. 在Excel中准备两列：
```
IP地址         端口
1.2.3.4       443
5.6.7.8       8080
```

2. 选中数据 → Ctrl+C 复制

3. 粘贴到管理面板的输入框

4. 点击 **检测清洗** → **追加入库**

### 从远程URL加载IP

1. 切换到 **远程TXT** 标签页

2. 输入TXT文件URL（如GitHub Raw文件）

3. 点击 **加载** → **追加入库**

### 域名探测

在 **Check ProxyIP** 区域：
```
# 探测A记录
example.com
example.com:8080

# 探测TXT记录
txt@example.com
```

自动检测IP可用性，点击 **➕** 添加到输入框

</details>

<details>
<summary><strong>⚙️ 环境变量说明（点击展开）</strong></summary>

### 📝 环境变量是什么？

**环境变量**就像是应用程序的配置参数，你告诉程序"谁"（哪个账号）、"管理什么"（哪些域名）、"怎么工作"（用什么模式）。

### 必填变量（必须设置）

| 变量名 | 说明 | 示例 | 备注 |
|--------|------|------|----------|
| `CF_MAIL` | 目标维护域名所托管的Cloudflare 账号邮箱 | `user@example.com` | 目标维护域名托管的账号邮箱 |
| `CF_KEY` | 目标维护域名所托管的Cloudflare API Token（带dns编辑即可 ）| `abcd1234...` | 目标维护域名的API Token |
| `CF_ZONEID` | 目标维护域名的 Zone ID | `1a2b3c4d...` | 你刚才复制的Zone ID |
| `CF_DOMAIN` | 目标要维护的域名，具体配置（见下方格式说明） | `txt@ddns.example.com:port&3` | 你想管理的域名（最重要！） |
| `CHECK_API` | ProxyIP检测API地址（下方有项目地址） | `https://check.dwb.pp.ua/check?proxyip=` | IP检测服务地址（建议自建） |

### 可选变量（按需设置）

| 变量名 | 说明 | 默认值 | 示例 |
|--------|------|--------|------|-------------------|
| `DOH_API` | DNS over HTTPS API | `https://cloudflare-dns.com/dns-query` | 其他DoH服务 | 
| `TG_TOKEN` | Telegram Bot Token | 无 | `1234567890:ABCdef...` |
| `TG_ID` | Telegram Chat ID | 无 | `123456789` | 
| `IP_INFO_ENABLED` | 查询ip归属地开关 | `false` | `true` | 
| `IP_INFO_API` | 查询ip归属地api | `http://ip-api.com/json` | `https://example.com/json` | 

### 🎯 CF_DOMAIN 配置详解（这是最重要的配置！）

```
# 基础格式：
# [模式]@域名:[端口]&[最小活跃数]

# 示例：维护域名 ddns.example.com
CF_DOMAIN="ddns.example.com:2053&5"
# 解读：维护A记录，端口2053，最少保持5个活跃IP
```

#### 三种模式选择：

**1. A记录模式（最常用）**
```bash
CF_DOMAIN="ddns.example.com"                    # 默认端口443
CF_DOMAIN="ddns.example.com:8443"               # 指定端口8443
CF_DOMAIN="ddns.example.com:8080&3"             # 端口8080，最少3个活跃IP
```

**2. TXT记录模式**
```bash
CF_DOMAIN="txt@txt.example.com"                 # TXT记录，存储IP:PORT列表
CF_DOMAIN="txt@txt.example.com&5"              # 最少5个活跃IP
```

**3. 双模式（高级）**
```bash
CF_DOMAIN="all@multi.example.com:8080"          # 同时维护A和TXT记录
```

#### 多域名配置（同时管理多个域名）

```bash
# 用逗号分隔不同域名的配置
CF_DOMAIN="ddns1.example.com:443,txt@txt.example.com,all@multi.example.com:8080&3"

# 解读：
# 1. ddns1.example.com:443 - A记录模式，端口443
# 2. txt@txt.example.com   - TXT记录模式
# 3. all@multi.example.com:8080&3 - 双模式，端口8080，最少3个活跃IP
```

### ⚡ 快速配置建议

对于大多数用户，建议这样配置：

```bash
# 新手推荐：管理一个域名，端口443，最少3个活跃IP
CF_DOMAIN="your-domain.com:443&3"

# 进阶用户：管理多个域名
CF_DOMAIN="proxy1.example.com:443,txt@ip-list.example.com,proxy2.example.com:8080&5"
```

**配置后记得**：保存配置 → 重新部署Worker → 测试是否正常工作

</details>

<details>
<summary><strong>🔧 参数配置（点击展开）</strong></summary>

### 调整并发检测数量

在代码中修改 `GLOBAL_SETTINGS`：

```javascript
const GLOBAL_SETTINGS = {
    CONCURRENT_CHECKS: 10,      // 并发数：10（网络好可改为15-20）
    CHECK_TIMEOUT: 6000,        // 超时：6秒
    REMOTE_LOAD_TIMEOUT: 10000  // 远程加载超时：10秒
    IP_INFO_TIMEOUT: 6000       // ip归属地查询超时：6秒
};
```

### 自建 IP 检测 API

参考项目：[CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP)

部署后修改 `CHECK_API` 环境变量为你的 API 地址。

### Telegram 通知配置

1. 创建 Telegram Bot：与 [@BotFather](https://t.me/botfather) 对话
2. 获取 Token：`123456789:ABCdefGHIjklMNOpqrsTUVwxyz`
3. 获取 Chat ID：与 [@userinfobot](https://t.me/userinfobot) 对话
4. 配置环境变量 `TG_TOKEN` 和 `TG_ID`

</details>

<details>
<summary><strong>🛠️ 工作原理（点击展开）</strong></summary>

### 维护流程

```
1. 定时触发（Cron）或手动触发
   ↓
2. 检测现有DNS记录中的IP/txt记录中的ip
   ↓
3. 删除失效IP 
   ↓
4. 如果活跃IP < MIN_ACTIVE（最小活跃ip数）
   └─ 从 IP_DATA (KV) 加载库存
   ↓
5. 检测有效ip并添加到DNS/txt记录
   ↓
6. 更新记录和库存数量
   ↓
7. 发送Telegram通知
```

</details>

<details>
<summary><strong>❓ 常见问题（点击展开）</strong></summary>

### 🆘 常见问题

#### 1. 为什么检测清洗后库存没变化？

**问题描述**：我输入了一些IP，点击了"检测清洗"，但是库存数量没有增加。

**原因**：检测清洗只验证当前输入框中的IP是否可用，并不会自动保存到库存。

**解决方案**：检测清洗后，请点击 **追加入库** 按钮，这样才会把可用的IP保存到库存中。

#### 2. 如何获取 Cloudflare API Token？

**获取步骤**：
1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 右上角头像 → **My Profile** → **API Tokens**
3. **Create Token** → 使用 **Edit zone DNS** 模板
4. 选择需要管理的域名 → **Continue to summary** → **Create Token**

**重要提醒**：
- Token只显示一次！请立即复制保存
- 使用"Edit zone DNS"模板就足够了，不需要其他权限
- 如果Token丢失，需要重新创建一个

#### 3. 如何找到 Zone ID？

**方法一**：
1. 登录 Cloudflare Dashboard
2. 点击左侧你的域名
3. 右侧 **API** 区域可以看到 **Zone ID**

**方法二**：
1. 在域名概览页面的右侧边栏
2. 找到"API"部分，点击"Zone ID"旁边的复制按钮

#### 4. 定时任务不工作？

**可能原因和检查步骤**：

1. **检查Cron配置**：
   - 进入 Worker → **Triggers** → **Cron Triggers**
   - 确保已添加了Cron表达式（如 `0 */3 * * *`）
   - 检查状态是否为"Enabled"

2. **检查执行日志**：
   - Dashboard → Worker → **Logs**
   - 查看是否有定时触发的日志记录

3. **常见问题**：
   - **免费计划限制**：Cloudflare Workers免费计划支持Cron，但可能有延迟
   - **Cron表达式错误**：确保格式正确，如 `0 */3 * * *` 表示每3小时执行

#### 5. IP检测一直失败？

**检查清单**：

1. **检查CHECK_API配置**：
   - 确保 `CHECK_API` 环境变量配置正确
   - 默认值：`https://check.dwb.pp.ua/check?proxyip=`
   - 可以浏览器打开测试：`https://check.dwb.pp.ua/check?proxyip=1.2.3.4:443`

2. **检查IP格式**：
   - 必须包含端口，如 `1.2.3.4:443`
   - 不能是 `1.2.3.4`（缺少端口）
   - 端口必须在1-65535范围内

3. **检查目标端口**：
   - 确保目标IP的端口是开放的
   - 可以使用 `telnet IP 端口` 命令测试连通性


## 📚 相关项目

本项目基于以下优秀项目：

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) - CF ProxyIP检测API
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D) - DDNS-cf域名

## 📄 License

[MIT License](https://github.com/231128ikun/DDNS-cf-proxyip/blob/main/LICENSE)

## 📮 联系方式

如有问题，请在 GitHub 提交 Issue。
