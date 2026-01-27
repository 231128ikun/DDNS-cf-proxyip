# DDNS Pro - Cloudflare Workers 动态DNS & IP管理

多域名动态DNS管理系统，支持A记录、TXT记录和双模式，自动检测并替换失效IP。

## 📋 主要功能

- ✅ **多域名管理** - 支持同时管理多个域名的DNS记录
- ✅ **三种模式** - A记录、TXT记录、双模式（ALL）
- ✅ **自动维护** - 定时检测失效IP并自动补充
- ✅ **批量检测** - 并发检测IP可用性，提高效率
- ✅ **追加入库** - 新IP追加到库存，不覆盖现有数据
- ✅ **Telegram通知** - 维护完成后推送详细报告
- ✅ **Web管理界面** - 直观的可视化操作面板

## 🚀 快速部署

### 1. 准备工作

- Cloudflare账号
- Cloudflare API Token（需要DNS编辑权限）
- Zone ID（域名的区域ID）
- （可选）Telegram Bot Token 和 Chat ID

### 2. 部署到 Cloudflare Workers

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 **Workers & Pages**
3. 点击 **Create Application** → **Create Worker**
4. 复制 `worker.js` 的完整代码
5. 粘贴到编辑器并点击 **Save and Deploy**
6. 进入 **Settings** → **Variables** 配置环境变量
7. 进入 **Settings** → **Bindings** 创建 KV 绑定（变量名: `IP_DATA`）

### 3. 配置环境变量

在 Cloudflare Dashboard 的 Worker 设置中添加：

# 环境变量
[vars]
```
CF_MAIL = "your-email@example.com"
CF_KEY = "your-cloudflare-api-token"
CF_ZONEID = "your-zone-id"
CF_DOMAIN = "ddns.example.com,all@proxy.example.com:8443,txt@txt.example.com"
MIN_ACTIVE = "3"
DOMAIN = "source.example.com:443"
CHECK_API = "https://check.dwb.pp.ua/check?proxyip="
DOH_API = "https://cloudflare-dns.com/dns-query"
```
（这里的cf变量CF_MAIL、CF_KEY、CF_ZONEID、CF_DOMAIN是你要维护的域名托管的cf账号信息）

# Telegram 通知（可选）
TG_TOKEN = "your-telegram-bot-token"
TG_ID = "your-telegram-chat-id"

# 定时任务（Cron Triggers）
[triggers]
crons = ["0 */6 * * *"]  # 每6小时执行一次维护
```

## ⚙️ 环境变量说明

### 必填变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `CF_MAIL` | Cloudflare 账号邮箱 | `user@example.com` |
| `CF_KEY` | Cloudflare API Token | `abcd1234...` |
| `CF_ZONEID` | 域名的 Zone ID | `1a2b3c4d...` |
| `CF_DOMAIN` | 目标域名配置（见下方格式说明） | `ddns.example.com` |
| `MIN_ACTIVE` | 最少活跃IP数量 | `3` | `5` |
| `CHECK_API` | IP检测API地址 | `https://check.dwb.pp.ua/check?proxyip=` | 自建API地址 |
### 可选变量

| 变量名 | 说明 | 默认值 | 示例 |
|--------|------|--------|------|
| `DOMAIN` | 源域名（自动解析为候选IP） | 无 | `source.example.com:443` |
| `DOH_API` | DNS over HTTPS API | `https://cloudflare-dns.com/dns-query` | 其他DoH服务 |
| `TG_TOKEN` | Telegram Bot Token | 无 | `1234567890:ABCdef...` |
| `TG_ID` | Telegram Chat ID | 无 | `123456789` |

### CF_DOMAIN 格式说明

支持三种模式，多个域名用逗号分隔：

```bash
# A记录模式（默认）
CF_DOMAIN="ddns.example.com"                    # 默认端口443
CF_DOMAIN="ddns.example.com:8443"               # 指定端口8443

# TXT记录模式
CF_DOMAIN="txt@txt.example.com"                 # TXT记录，存储 IP:PORT 列表

# 双模式（同时维护A和TXT记录）
CF_DOMAIN="all@multi.example.com:8080"          # 同时创建A记录和TXT记录

# 多域名配置（逗号分隔）
CF_DOMAIN="ddns.example.com,txt@txt.example.com,all@multi.example.com:8080"
```

## 📖 使用指南

### 1. 访问管理面板

部署完成后，访问你的 Worker 地址：
```
https://your-worker-name.your-subdomain.workers.dev
```

### 2. IP 管理操作

#### 添加 IP 到库存

1. 在 **手动输入** 标签页输入IP（支持多种格式）
2. 点击 **检测清洗** - 自动验证并过滤失效IP
3. 点击 **追加入库** - 将有效IP追加到库存

**支持的IP格式：**
```
1.2.3.4:443
1.2.3.4 443
1.2.3.4	443     ← Tab分隔（Excel复制）
1.2.3.4：443    ← 中文冒号
1.2.3.4         ← 默认端口443
```

#### 从远程加载 IP

1. 切换到 **远程TXT** 标签页
2. 输入远程TXT文件URL
3. 点击 **加载** - 自动下载并格式化

#### 查看IP库存

1. 切换到 **IP库** 标签页
2. 点击 **加载库存** 查看所有库存IP

### 3. 域名解析管理

#### 手动添加IP到DNS

在 **解析实况** 区域：
1. 输入IP地址
2. 点击 **添加** - 自动检测并添加A记录

#### 查看当前解析状态

点击 **刷新** 按钮查看：
- A记录列表（IP、机房、延迟、状态）
- TXT记录内容（如果是TXT或ALL模式）

#### 删除失效记录

点击每个记录后的 **🗑️** 图标删除

### 4. 域名探测

在 **Check ProxyIP** 区域：

```bash
# 探测A记录
example.com           # 默认端口443
example.com:8080      # 指定端口

# 探测TXT记录
txt@example.com
```

自动检测每个IP的可用性，可点击 **➕** 添加到输入框

### 5. 定时维护

#### 手动维护

点击 **执行全部维护** 按钮，系统会：
1. 检测所有DNS记录中的IP/txt记录中的ip
2. 删除失效的IP
3. 从库存中补充新IP（保证最少活跃数量）
4. 发送Telegram通知（如已配置）

#### 自动维护

在 `wrangler.toml` 中配置定时任务：

```toml
[triggers]
crons = ["0 */6 * * *"]  # 每6小时执行一次

# 更多示例：
# "0 */2 * * *"   # 每2小时
# "0 0 * * *"     # 每天0点
# "0 */30 * * *"  # 每30分钟
```

## 🔧 高级配置

### 调整并发检测数量

在代码中修改 `GLOBAL_SETTINGS`：

```javascript
const GLOBAL_SETTINGS = {
    CONCURRENT_CHECKS: 10,      // 并发数：10（网络好可改为15-20）
    CHECK_TIMEOUT: 6000,        // 超时：6秒
    REMOTE_LOAD_TIMEOUT: 10000  // 远程加载超时：10秒
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

## 🛠️ 工作原理

### 维护流程

```
1. 定时触发（Cron）或手动触发
   ↓
2. 检测现有DNS记录中的IP/txt记录中的ip
   ↓
3. 删除失效IP 
   ↓
4. 如果活跃IP < MIN_ACTIVE
   ├─ 从 DOMAIN（若配置） 解析新IP
   └─ 从 IP_DATA (KV) 加载库存
   ↓
5. 检测候选IP
   ↓
6. 添加有效IP到DNS
   ↓
7. 更新库存
   ↓
8. 发送Telegram通知
```

## 📚 相关项目

本项目基于以下优秀项目：

- [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) -CF ProxyIP检测API
- [CF-Workers-DD2D](https://github.com/cmliu/CF-Workers-DD2D) - DDNS-cf域名

## ❓ 常见问题

### 1. 为什么检测清洗后库存没变化？

检测清洗只处理当前输入框中的IP，不会影响库存。如需更新库存，请先检测清洗，再点击 **追加入库**。

### 2. 如何获取 Cloudflare API Token？

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 右上角头像 → **My Profile** → **API Tokens**
3. **Create Token** → 使用 **Edit zone DNS** 模板
4. 选择需要管理的域名 → **Continue to summary** → **Create Token**

### 3. 如何找到 Zone ID？

1. 登录 Cloudflare Dashboard
2. 选择域名
3. 右侧 **API** 区域可以看到 **Zone ID**

### 4. 定时任务不工作？

Cloudflare Workers 的免费计划支持 Cron Triggers。检查：
1. `wrangler.toml` 中是否配置了 `[triggers]`
2. 在 Dashboard 的 Worker → **Triggers** → **Cron Triggers** 查看是否生效
3. 查看执行日志：Dashboard → Worker → **Logs**

### 5. IP检测一直失败？

检查：
1. `CHECK_API` 是否配置正确且可访问
2. IP格式是否正确（必须包含端口）
3. 目标端口是否开放

## 📄 License

[MIT License](https://github.com/231128ikun/DDNS-cf-proxyip/blob/main/LICENSE)

## 📮 联系方式

如有问题，请在 GitHub 提交 Issue。
