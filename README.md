# grain

单机版 Go/Gin IAM 服务脚手架，提供用户、角色、菜单、按钮、API 权限、JWT 登录与刷新令牌轮换。

## 环境要求

- Go 1.27+
- SQLite（默认开发配置）、MySQL、PostgreSQL、SQL Server 或 openGauss 之一

## 快速启动

仓库已包含可直接运行的开发配置 `config/config.yaml` 和**仅用于本地开发**的 RSA 私钥
`config/dev-signing-key.pem`。

```bash
# 1. 初始化数据库
go run . -conf config/config.yaml -migrate

# 2. 启动服务
go run . -conf config/config.yaml
```

验证：

```bash
curl http://127.0.0.1:8080/livez
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/jwks.json
```

`-conf` 现在指向**配置文件**；SQLite 相对路径、JWT 私钥/公钥相对路径均相对于配置文件所在目录解析。

## 生产部署前必须修改

1. **替换 JWT 私钥**。`config/dev-signing-key.pem` 是公开的开发密钥，任何拿到仓库的人都能伪造令牌。
   生成新私钥并配置 `security.token.private_key`：

   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
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

3. **多实例部署启用 Redis**：

   ```yaml
   redis:
     enable: true
     addr: "redis:6379"
     password: "从 Secret 注入的密码"
     db: 0
   ```

   Redis 用于 token version 热缓存、刷新令牌轮换与 family 吊销状态；数据库仍是吊销基线的权威来源。

4. **限制 CORS 与 Host**，并关闭不需要的 Swagger / pprof / metrics 暴露。

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

**注意**：当前运行时策略变更只更新处理该请求的实例。多实例部署时，其他实例要等到重启
（或后续实现基于 `iam_policy_revision` 的同步机制）才会看到变更；在此之前请将 IAM 写操作
限制在单实例，或通过负载均衡固定到单一实例。

## 账号与会话

- 密码使用 bcrypt 存储。
- **登录失败锁定**：`security.login.max_failed_attempts` 控制阈值，达到后账号锁定
  `lock_duration`；锁定期间即使密码正确也会被拒绝。成功登录会清零失败计数。
  计数存储与 token 状态一致：启用 Redis 时多实例共享，否则使用进程内存。
  不存在的用户名同样计数，避免通过锁定行为枚举账号。修改密码、管理员重置密码或重新
  启用账号会清除失败计数。
- **密码强度**：`security.password.strength_level` 支持 0–3：
  - `0`：至少 6 位；
  - `1`：至少 8 位；
  - `2`：至少 8 位且同时包含字母和数字；
  - `3`：至少 10 位且包含大写、小写、数字和特殊字符。

  策略统一作用于创建用户、修改密码、管理员重置密码和用户更新接口中的密码字段。
  bcrypt 只使用前 72 字节，因此超过 72 字节的密码会被拒绝；包含空白或控制字符的密码
  同样会被拒绝。
- `PUT /api/v1/users/{id}` 中未传 `is_active` 时保留原有启用状态；显式传 `false` 才会禁用。
  更新密码、角色变更或禁用都会递增 token version 并吊销已有会话。
- `security.token.refresh_method` 当前必须与 `access_method` 一致；访问令牌和刷新令牌共用
  同一签名算法与密钥。

## 测试

```bash
go test ./...
go test -race ./...
go vet ./...
```

核心包测试覆盖：`pkg/auth`、`pkg/db`、`pkg/cryptoutil`、中间件、IAM biz/data/service。

## 目录结构

```
main.go                    启动、配置、迁移、HTTP 服务
internal/conf              配置结构与校验
internal/server/iam        路由注册、依赖装配、策略重建
internal/service/iam       HTTP handler / DTO
internal/biz/iam           业务用例
internal/data/iam          持久化、缓存、Casbin 同步
internal/middleware        认证、鉴权、限流、超时、CORS 等
pkg/auth                   JWT、JWKS、subject 规范
pkg/cryptoutil             密码哈希与加解密工具
pkg/db                     GORM 封装与错误映射
pkg/errorx                 统一错误码与 HTTP 响应
pkg/logx                   slog 日志适配
```
