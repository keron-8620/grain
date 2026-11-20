# grain

A single-node Go/Gin operations platform: IAM (users, roles, menus, buttons, API permissions, JWT login and refresh-token rotation), script scheduling, and host inventory (CMDB).

> **Deployment: single-node only. Multi-instance / horizontal scaling is not supported.**
> The cron scheduler, Casbin policies, replay-protection nonces and login-lockout counters are
> process-local; replicas would run schedules multiple times and diverge on authorization. Do not
> share one database between multiple grain instances or put them behind a load balancer.

## Requirements

- Go 1.27+
- SQLite (default for development), MySQL, PostgreSQL, SQL Server or openGauss

## Quick start

The repository ships a runnable development config (`config/config.yaml`). The development RSA
key is generated locally with `make dev-key` (writes `config/dev-signing-key.pem`, which is
git-ignored); no private key is tracked in git.

```bash
go run . -conf config/config.yaml -migrate          # schema bootstrap
go run . -conf config/config.yaml -exec-sql sql/database.sql  # roles + API catalog
go run . -conf config/config.yaml -bootstrap-admin  # create admin with a one-time random password
go run . -conf config/config.yaml                   # start HTTP server
```

`sql/database.sql` creates the `admin` role and the API catalog only; it no longer seeds any
account. `-bootstrap-admin` prints a 24-character random password exactly once (never to the
application log). Startup is refused while any account still uses the historical default password.

```bash
curl http://127.0.0.1:8080/livez
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/jwks.json
```

`-conf` points to a **file**. Relative SQLite DSNs and relative JWT key paths are resolved
against the config file's directory.

## Before production

1. Replace the development signing key with a private key injected from a secret store.
   The old development key is treated as leaked and is rejected by fingerprint at startup.
2. Run `grain -conf ... -migrate` as a separate deployment step.
   Use `-exec-sql /path/to/file.sql` for additional SQL, then `-bootstrap-admin` once to create
   the administrator with a random password.
3. Optionally enable Redis. Redis can hold the token-version hot cache and refresh-token
   rotation/family revocation state so it survives restarts; the database remains the
   authoritative revocation baseline. Redis does not enable multi-instance deployment.
4. Start from `config/config.prod.example.yaml` and set `server.mode: "prod"`. Production mode
   refuses to start with Swagger enabled, no TLS/proxy, HostGuard disabled or empty, wildcard
   CORS, zero rate limit/timeout, or a relative signing-key path. Terminate TLS at a reverse
   proxy (`behind_tls_proxy: true`) and keep grain bound to `127.0.0.1`.
5. Restrict CORS/hosts and disable Swagger/pprof/metrics exposure when not needed.
6. Health endpoints share the per-IP rate limit; make sure `server.rate.rps`/`burst` can cover
   kubelet/LB probe QPS, otherwise probes receive 429.

## Authorization model

- Model: `p = sub, obj, act`, `g = _, _`, matched with `keyMatch2`.
- API catalog rows produce `p` rules: `iam:api:<id>, URL, METHOD`.
- Role/menu/button relations produce `g` edges (role→API/menu/button, menu→parent/API,
  button→menu/API).
- Requests are enforced as `iam:role:<role_id>`.

At startup `ReconcileIAMPolicies` rebuilds every `iam:*` rule from the relational IAM tables
and preserves rules owned by other authorities. Casbin no longer uses the string adapter as
durable storage.

**Single-node note:** Casbin policies live in the process and are rebuilt from the IAM tables at
startup; runtime changes apply to this process immediately. There is no cross-instance sync, which
is why multi-instance deployment is not supported.

## Notes

- Passwords are stored with bcrypt.
- **Login lockout**: after `security.login.max_failed_attempts` consecutive failures the account
  is locked for `lock_duration`; even a correct password is rejected while locked. A successful
  login clears the counter. Counters are shared through Redis when enabled, otherwise held in
  process memory. Unknown usernames are counted too, preventing lockout-based enumeration.
  Changing/resetting the password or re-enabling an account clears the counter.
- **Password strength**: `security.password.strength_level` supports 0–3:
  - `0`: at least 6 characters;
  - `1`: at least 8 characters;
  - `2`: at least 8 characters with letters and digits;
  - `3`: at least 12 characters with upper/lowercase letters, digits and a symbol.

  The policy applies to user creation, password changes, admin resets and password updates.
  Passwords longer than 72 bytes are rejected because bcrypt ignores the remainder; passwords
  containing whitespace or control characters are rejected as well.
- `PUT /api/v1/users/{id}` preserves `is_active` when omitted; explicit `false` disables the
  account. Password/role changes and disabling revoke existing sessions.
- `security.token.refresh_method` must currently match `access_method`; access and refresh
  tokens share the same signing algorithm and key.

`sql/database.sql` creates the `admin` role and API catalog without seeding any account. Run
`grain -bootstrap-admin` once to create the administrator with a one-time random password; run the
script only once on a fresh database.

## Scripts, schedules and hosts

- **Scripts**: metadata lives in `job_script`; source is stored in the configured Git repository
  (`job.script_repo.enable: true`) or in `storage/script` (`enable: false`, the single-node default).
  API: `/api/v1/scripts`, including `GET /api/v1/scripts/{id}/content`.
- **Schedules**: cron expressions at `/api/v1/schedules`, with create/update/delete,
  enable/disable and run-now (`/schedules/{id}/run`).
- **Executions**: `/api/v1/script-records` for triggering, listing, canceling and downloading logs
  (`/script-records/{id}/log`). `host_id=0` runs locally; otherwise SSH/WinRM is used.
- **Hosts**: `/api/v1/hosts`; SSH onboarding deploys the configured public keys and exports Ansible
  host vars to `storage/host_vars`. At startup every host's vars are rewritten from the database,
  removing legacy `ansible_password` and inline PEM fields.
- **Git over SSH**: host keys are verified. The default known_hosts paths are used unless
  `job.script_repo.known_hosts` points to a file or `job.script_repo.ssh_host_key` pins the server
  key; without either, the SSH repository is rejected at startup.
- **SSH host keys**: create/update skips verification and pins the server key (TOFU); later remote
  executions verify against it and refuse a mismatch. After a host rebuild or key rotation call
  `POST /api/v1/hosts/{id}/refresh-key`; hosts created before this feature need one refresh too.
- These endpoints reuse IAM JWT authentication and Casbin authorization. Job/CMDB routes are added
  to the `iam_api` catalog at startup, so a role must be granted the matching API permissions first.
- Configuration lives under `job` / `cmdb` in `config/config.yaml`. Remote execution is
  passwordless: SSH reuses `cmdb.ssh_private_key` (optional
  `ssh_private_key_passphrase`), WinRM uses client certificates only. host_vars stores key/cert
  **paths**, never passwords or key material; the database stores no host password.
  `cmdb.ssh_password` is only a first-contact fallback for installing the public key and is never
  persisted.

## Tests

```bash
go test ./...
go test -race ./...
go vet ./...
```
