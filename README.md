# NodeCrypt

> 纯前端端到端加密聊天，Cloudflare Workers / Durable Objects 后端。已要求账号登录，历史密文可持久化。

## 部署方式
- **方法一：一键部署到 Cloudflare Workers**（主分支镜像，不会自动跟随上游）：  
  构建：`npm run build`；部署：`npm run deploy`
- **方法二：Fork+自动同步（推荐长期维护）**：  
  1) fork 本仓库；2) Workers 控制台选择 “Import from GitHub” 绑定 fork；构建：`npm run build`；部署：`npm run deploy`。上游更新会自动同步到你的 fork 并重新部署。
- **方法三：Docker 自托管**（需自配 HTTPS，否则密钥传输会失败）：  
  `docker run -d --name nodecrypt -p 80:80 ghcr.io/shuaiplus/nodecrypt`
- **方法四：本地开发**：`npm install && npm run dev`，部署 `npm run deploy`

## 🆕 账号 + 历史（保持端到端加密）
- 必须注册/登录账号（邮箱验证码注册/登录），不再允许匿名进入。
- 历史消息以“归档密文”存储，使用房间密码派生的密钥在客户端解密；服务器只保存密文与必要元数据，永远看不到明文。
- 邮箱验证码通过 Cloudflare Workers 内置 MailChannels 发送，需设置 `MAIL_FROM`（你的域名邮箱，配置好 SPF/DKIM）。
- 存储使用 D1，仅存密文和索引，不存房间密码/明文。

### 新增 API
- `POST /api/auth/send-code { email }`
- `POST /api/auth/register { username, email, password, code }`
- `POST /api/auth/login { identifier, password }` // identifier = 用户名或邮箱
- `GET /api/history?dialog=<id>&after=<id>&limit=50` // 需 Bearer token

## 项目简介
NodeCrypt 是一个真正的端到端加密聊天系统，采用零知识架构。服务器、网络中间人、甚至管理员都无法获取明文；加解密全部在客户端完成，服务器仅做加密数据中转。

### 系统架构
- 前端：ES6+ 模块化 JS，无框架依赖
- 后端：Cloudflare Workers + Durable Objects
- 通信：WebSocket 实时双向
- 构建：Vite

## 零知识架构设计
### 核心原则
- 服务器盲中继：服务器永远无法解密消息，仅转发密文
- 端到端加密：全程加密，中间节点不可读
- 前向安全：历史密文需房间密码解密，妥善保管房间密码
- 账号登录：必须注册/登录，服务器只存密文索引
- 丰富体验：图片/文件、主题、多语言

### 隐私保护
- 实时成员提醒：有人加入/离开全员可见
- 历史密文拉取：仅登录且加入房间的用户可获取，需房间密码解密
- 私聊加密：头像点击发起端到端私聊

### 房间密码机制
`最终共享密钥 = ECDH 共享密钥 XOR SHA256(房间密码)`  
不同密码的房间互不可解；服务器永远不知道房间密码。

### 三层安全
1) RSA-2048 服务器身份，24h 轮换（空闲时）  
2) ECDH-P384 握手，AES-256 传输密钥  
3) ChaCha20 客户端消息密钥，AES-256 外层封装

## 完整加密流程（简述）
- 连接时校验 RSA 公钥 -> P-384 ECDH 导出 AES-256 与服务器加密通道  
- 加入房间：发送房间哈希；服务器仅记内存列表  
- 客户端间：Curve25519 密钥交换 + 房间密码 XOR 得到会话密钥，消息体用 ChaCha20，加一层 AES-256 给服务器转发  
- 历史存储：客户端用房间密码派生密钥将消息“归档密文”一并发给服务器存储，服务器不解密

## Cloudflare Workers 部署（含账号/历史）
1) 安装依赖并构建前端  
   ```bash
   npm install
   npm run build
   ```
2) 创建 D1 数据库并拿到 `database_id`（必须先做这一步）  
   ```bash
   npm run d1:create   # 等同 wrangler d1 create nodecrypt-db
   ```
   如果 `wrangler.toml` 里还保留占位符 `REPLACE_WITH_D1_ID`，可用“全自动”部署脚本自动创建并写入：  
   ```bash
   npm run deploy:auto   # 自动创建 D1（若占位符存在）-> 应用 schema -> deploy
   ```
   若已写入真实 ID，则跳过这一步。
3) 编辑 `wrangler.toml`，把 `database_id` 替换成上一步的真实 ID（若使用 deploy:auto 且存在占位符，会自动完成）：  
   ```toml
   [[d1_databases]]
   binding = "DB"
   database_name = "nodecrypt-db"
   database_id = "<你的 database_id>"
   ```
   也可以在部署环境里设置环境变量 `D1_ID`（或 `D1_DATABASE_ID`），脚本会自动用该值替换占位符。
   同理 `account_id` 占位符可用 `ACCOUNT_ID`/`CF_ACCOUNT_ID` 环境变量自动填充；可选 `D1_LOCATION`（默认 weur）。
4) 初始化表结构  
   ```bash
   npm run d1:schema   # 等同 wrangler d1 execute nodecrypt-db --file=worker/db-schema.sql
   ```
5) 设置邮件发件人（MailChannels）  
   ```bash
   wrangler secret put MAIL_FROM   # 例如 no-reply@yourdomain.com，域名需 SPF/DKIM
   ```
6) 登录并部署（`npm run deploy` 会自动创建 D1/写入 ID/跑 schema 后再 deploy；若 ID 已设置则跳过创建）  
   ```bash
   wrangler login
   npm run deploy
   ```
7) 验证  
   ```bash
   wrangler tail
   # 前端注册/登录 -> 进入房间 -> 发送消息 -> 刷新确认历史可加载并能解密
   ```

## 安全建议
- 使用强房间密码并妥善保存；密码泄露则历史可被解密
- 保持浏览器更新，确保 WebCrypto 安全
- 如公开部署，请开启 HTTPS（否则密钥协商会失败）
