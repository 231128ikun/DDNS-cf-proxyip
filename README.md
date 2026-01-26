本项目基于 Cloudflare Workers 运行，利用 KV 存储 IP 池，实现自动化的解析维护。

#### 第一步：准备工作
1.  **获取 Zone ID**：在 Cloudflare 域名概述页右侧找到“区域 ID”。
2.  **获取 API 令牌**：在“我的个人资料”->“API 令牌”中创建一个具有 `Zone.DNS` 修改权限的令牌。

#### 第二步：部署脚本
1.  新建一个 Cloudflare Worker，将 `Worker.js` 的全量代码粘贴进去。
2.  **绑定 KV（关键）**：
    *   在 Worker 设置页面找到 **Variables（变量）** -> **KV Namespace Bindings**。
    *   创建一个名为 `IP_DATA` 的 KV 空间并绑定到 Worker 上。
3.  **配置环境变量**（在 Variables 页面添加）：
    *   `CF_MAIL`: 你的 CF 邮箱（要维护的域名所在cf账号）。
    *   `CF_KEY`: 你的 API 令牌。（同上）
    *   `CF_ZONEID`: 你的区域 ID。（同上）
    *   `CF_DOMAIN`: **目标维护域名**（如 `kr.dwb.cc.cd`）。
    *   `TARGET_PORT`: 维护的端口（如 `50001` 或 `443`）。
    *   `MIN_ACTIVE`: 最小活跃 IP 数量（如 `3`）。
    *   `CHECK_API`: (可选) 后端检测接口地址，例如：`https://check.dwb.pp.ua/check?proxyip=`，[项目地址](https://github.com/cmliu/CF-Workers-CheckProxyIP)。
    *   `REMOTE_URLS`: (可选) 远程 TXT 订阅库地址，多个用逗号隔开。

#### 第三步：设置自动化（定时任务）
1.  在 Worker 设置页面找到 **Triggers（触发器）** -> **Cron Triggers**。
2.  添加一个触发器，例如 `0 */3 * * *`（每 3个小时执行一次自动维护）。

---

### 📖 如何使用

1.  **初始化库**：
    *   打开 Worker 提供的 URL 进入控制面板。
    *   粘贴你的 IP 列表（支持 `IP 端口`、`IP:端口` 等乱序格式）到文本框。
    *   点击 **「✅ 保存并添加」**，系统会自动去重并规范化。
2.  **手动维护**：
    *   点击 **「启动补齐维护」**：后端会立即检查当前域名解析，删掉坏的 IP，并从库里找好的补齐。
3.  **批量洗库**：
    *   如果你库里 IP 太多，点击 **「⚡ 一键检测并入库」**。前端会并发检测所有 IP 存活情况，并自动剔除死 IP 后更新数据库。
4.  **外部探测**：
    *   在 `Check ProxyIP` 输入别人的域名或 `域名:端口`，点击探测。解析出来的 IP 若有效，可点 **「追加」** 直接收入你的库中。
