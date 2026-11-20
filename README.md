# grain

单机版 Go/Gin 运维管控平台，包含 IAM（用户、角色、菜单、按钮、API 权限、JWT 登录与刷新令牌轮换）、
脚本任务调度（脚本、计划任务、执行记录）与主机管理（CMDB）。

> **部署形态：仅支持单机部署，不支持多实例/水平扩展。**
> 计划任务调度器、Casbin 策略、防重放 nonce、登录失败计数都在进程内；多副本会重复执行
> 计划任务，并出现授权状态不一致。请勿让多个 grain 实例共享同一数据库，也不要通过负载均衡
> 把流量分发给多个实例。

## 环境要求

- Go 1.27+
- SQLite（默认开发配置）、MySQL、PostgreSQL、SQL Server 或 openGauss 之一

## 快速启动

仓库包含可直接运行的开发配置 `config/config.yaml` 和**仅用于本地开发**的 RSA 私钥生成目标
`make dev-key`（生成 `config/dev-signing-key.pem`，该文件已被 `.gitignore` 忽略）。

```bash
# 1. 初始化数据库
go run . -conf config/config.yaml -migrate

# 2. 导入sql脚本
go run . -conf config/config.yaml -exec-sql sql/database.sql

# 3. 创建初始管理员（生成一次性随机口令并打印）
go run . -conf config/config.yaml -bootstrap-admin

# 4. 启动服务
go run . -conf config/config.yaml
```

`sql/database.sql` 只创建 `admin` 角色与 API 目录，**不再创建任何默认账号**。第一个管理员
通过 `-bootstrap-admin` 创建：命令生成 24 位随机口令并只打印一次，不会写入日志。服务启动时
若检测到仍在使用历史默认口令（`Admin@123456`）的账号，会拒绝启动并提示用该命令重置。
该脚本只应在全新数据库上执行一次。

验证：

```bash
curl http://127.0.0.1:8080/livez
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/jwks.json
```

`-conf` 现在指向**配置文件**；SQLite 相对路径、JWT 私钥/公钥相对路径均相对于配置文件所在目录解析。

## 生产部署前必须修改

1. **替换 JWT 私钥**。仓库不再跟踪开发私钥；本地开发用 `make dev-key` 生成
   `config/dev-signing-key.pem`（已被 `.gitignore` 忽略）。历史版本中出现过的旧开发密钥按
   **已泄露**处理，服务启动时会直接拒绝该指纹。生产环境必须使用受控 Secret 注入的私钥：

   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
     -out /secure/path/iam-signing-key.pem
   chmod 600 /secure/path/iam-signing-key.pem
   ```

   生产环境应通过 Secret/挂载文件注入，私钥不要进入镜像或 Git。

2. **迁移数据库**：部署时单独执行：

   ```bash
   grain -conf /etc/grain/config.yaml -migrate
   ```

   `-migrate` 执行 IAM 表的 schema 同步后退出；如需执行额外 SQL：
   `grain -conf ... -exec-sql /path/to/file.sql`。

3. **（可选）启用 Redis**：

   ```yaml
   redis:
     enable: true
     addr: "redis:6379"
     password: "从 Secret 注入的密码"
     db: 0
   ```

   单机部署可以不启用 Redis。启用后用于 token version 热缓存、刷新令牌轮换与 family 吊销
   状态，进程重启后状态不丢失；数据库仍是吊销基线的权威来源。**Redis 不代表支持多实例。**

4. **限制 CORS 与 Host**，并关闭不需要的 Swagger / pprof / metrics 暴露。
5. **为探针预留限流额度**：`/livez`、`/readyz`、`/health` 与业务接口共用 IP 限流，
   请确保 `server.rate.rps`/`burst` 能覆盖 kubelet/LB 探针的 QPS，否则探针会被 429。

## 权限模型

- 策略模型：`p = sub, obj, act`，`g = _, _`，匹配使用 `keyMatch2`。
- API 目录（`iam_api`）生成 `p` 规则：`iam:api:<id>, URL, METHOD`。
- 角色、菜单、按钮之间的关系生成 `g` 规则：
  - 角色 → API / 菜单 / 按钮；
  - 菜单 → 父菜单 / API；
  - 按钮 → 菜单 / API。
- 中间件以 `iam:role:<role_id>` 作为请求主体执行 Casbin `Enforce`。

启动时 `ReconcileIAMPolicies` 会以 IAM 数据库表为权威重建全部 `iam:*` 规则，
并保留其他 authority 的规则。Casbin 不再使用字符串 adapter 作为持久化存储。

**单机说明**：Casbin 策略只保存在当前进程内，启动时从 IAM 关系表重建；运行时的策略变更
立即在本进程生效。项目按单机设计，不提供跨实例同步，因此**不支持多实例部署**。

## 账号与会话

- 密码使用 bcrypt 存储。
- **登录失败锁定**：`security.login.max_failed_attempts` 控制阈值，达到后账号锁定
  `lock_duration`；锁定期间即使密码正确也会被拒绝。成功登录会清零失败计数。
  计数存储与 token 状态一致：启用 Redis 时写入 Redis（重启不丢失），否则使用进程内存。
  不存在的用户名同样计数，避免通过锁定行为枚举账号。修改密码、管理员重置密码或重新
  启用账号会清除失败计数。
- **密码强度**：`security.password.strength_level` 支持 0–3：
  - `0`：至少 6 位；
  - `1`：至少 8 位；
  - `2`：至少 8 位且同时包含字母和数字；
  - `3`：至少 12 位且包含大写、小写、数字和特殊字符。

  策略统一作用于创建用户、修改密码、管理员重置密码和用户更新接口中的密码字段。
  bcrypt 只使用前 72 字节，因此超过 72 字节的密码会被拒绝；包含空白或控制字符的密码
  同样会被拒绝。
- `PUT /api/v1/users/{id}` 中未传 `is_active` 时保留原有启用状态；显式传 `false` 才会禁用。
  更新密码、角色变更或禁用都会递增 token version 并吊销已有会话。
- `security.token.refresh_method` 当前必须与 `access_method` 一致；访问令牌和刷新令牌共用
  同一签名算法与密钥。

## 脚本任务与主机管理

- **脚本**：元数据存 `job_script`，正文存 Git 仓库（`job.script_repo.enable: true`）或本地目录
  `storage/script`（`enable: false`，单机开发默认）。接口：`/api/v1/scripts`，含
  `GET /api/v1/scripts/{id}/content`。
- **计划任务**：cron 表达式，接口 `/api/v1/schedules`，支持创建、更新、删除、启停与立即执行
  （`/schedules/{id}/run`）。
- **执行记录**：接口 `/api/v1/script-records`，支持触发、查询、取消与日志下载
  （`/script-records/{id}/log`）。`host_id=0` 在本机执行，否则按主机协议通过 SSH/WinRM 执行。
- **主机**：接口 `/api/v1/hosts`；接入 SSH 主机时可自动部署免密公钥，Ansible host_vars 落盘到
  `storage/host_vars`。启动时会从数据库重写全部 host_vars，清除旧版本残留的
  `ansible_password` 和内嵌 PEM。
- **Git SSH**：不再跳过主机密钥校验。默认读取 `~/.ssh/known_hosts`/`/etc/ssh/ssh_known_hosts`，
  也可用 `job.script_repo.known_hosts` 指定文件，或用 `job.script_repo.ssh_host_key` 固定仓库
  服务器公钥；两者都没有时会拒绝启动 SSH 仓库。
- **SSH 主机密钥**：新增/修改主机时跳过校验并记录主机公钥（TOFU）；之后的远程脚本执行使用该
  公钥校验，指纹不一致会拒绝连接。主机重装或密钥变更后调用
  `POST /api/v1/hosts/{id}/refresh-key` 重新采集；升级前已录入的主机也需要刷新一次。
  升级到该版本后请重新执行 `-migrate`，以新增 `job_host.ssh_host_key` 列。
- 以上接口复用 IAM 的 JWT 认证与 Casbin 鉴权。启动时 job/cmdb 路由会自动补录到 `iam_api` 并生成
  `p` 规则，需在角色中分配对应 API 权限后才能调用。
- 配置位于 `config/config.yaml` 的 `job` / `cmdb` 段。远程执行是**免密**的：SSH 复用
  `cmdb.ssh_private_key`（可带 `ssh_private_key_passphrase`），WinRM 仅支持客户端证书；
  host_vars 只记录私钥/证书**路径**，不记录密码或密钥内容，数据库也不保存主机密码。
  `cmdb.ssh_password` 仅作为首次接入时安装公钥的兜底，不会被持久化。

## 测试

```bash
go test ./...
go test -race ./...
go vet ./...
```

核心包测试覆盖：`pkg/auth`、`pkg/db`、`pkg/cryptoutil`、中间件、IAM/job/cmdb 各层。
`internal/server/job` 包含一条完整链路测试：登录 → RBAC → 创建脚本 → 本机执行 → 查询记录与日志。

## 目录结构

```
main.go                    启动、配置、迁移、HTTP 服务
internal/conf              配置结构与校验
internal/server/iam        IAM 路由注册、依赖装配、策略重建
internal/server/job        job 模块装配与路由注册
internal/server/cmdb       cmdb 模块装配与路由注册
internal/service/iam       IAM HTTP handler / DTO
internal/service/job       job HTTP handler / DTO
internal/service/cmdb      cmdb HTTP handler / DTO
internal/biz/iam           IAM 业务用例
internal/biz/job           脚本、计划任务、执行记录业务用例
internal/biz/cmdb          主机接入与主机台账业务用例
internal/data/iam          IAM 持久化、缓存、Casbin 同步
internal/data/job          脚本存储（Git/本地）、计划任务、执行记录持久化
internal/data/cmdb         主机持久化
internal/middleware        认证、鉴权、限流、超时、CORS 等
pkg/auth                   JWT、JWKS、subject 规范
pkg/cryptoutil             密码哈希与加解密工具
pkg/db                     GORM 封装与错误映射
pkg/errorx                 统一错误码与 HTTP 响应
pkg/logx                   slog 日志适配
pkg/remote                 SSH / WinRM 传输封装
```
