# grain

A single-node Go/Gin IAM scaffold providing users, roles, menus, buttons, API permissions, JWT login and refresh-token rotation.

## Requirements

- Go 1.27+
- SQLite (default for development), MySQL, PostgreSQL, SQL Server or openGauss

## Quick start

The repository ships a runnable development config (`config/config.yaml`) and a
**development-only** RSA key (`config/dev-signing-key.pem`).

```bash
go run . -conf config/config.yaml -migrate   # schema bootstrap
go run . -conf config/config.yaml            # start HTTP server
```

```bash
curl http://127.0.0.1:8080/livez
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/jwks.json
```

`-conf` points to a **file**. Relative SQLite DSNs and relative JWT key paths are resolved
against the config file's directory.

## Before production

1. Replace `config/dev-signing-key.pem` with a private key injected from a secret store.
   Never ship the development key.
2. Run `grain -conf ... -migrate` as a separate deployment step.
   Use `-exec-sql /path/to/file.sql` for additional SQL.
3. Enable Redis for multi-instance deployments. Redis stores the token-version hot cache and
   refresh-token rotation/family revocation state; the database remains the authoritative
   revocation baseline.
4. Restrict CORS/hosts and disable Swagger/pprof/metrics exposure when not needed.

## Authorization model

- Model: `p = sub, obj, act`, `g = _, _`, matched with `keyMatch2`.
- API catalog rows produce `p` rules: `iam:api:<id>, URL, METHOD`.
- Role/menu/button relations produce `g` edges (role→API/menu/button, menu→parent/API,
  button→menu/API).
- Requests are enforced as `iam:role:<role_id>`.

At startup `ReconcileIAMPolicies` rebuilds every `iam:*` rule from the relational IAM tables
and preserves rules owned by other authorities. Casbin no longer uses the string adapter as
durable storage.

**Limitation:** runtime policy mutations only update the instance handling the request. With
multiple instances, other replicas pick up changes on restart (or after a future
`iam_policy_revision` based synchronizer); keep IAM writes on a single instance for now.

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
  - `3`: at least 10 characters with upper/lowercase letters, digits and a symbol.

  The policy applies to user creation, password changes, admin resets and password updates.
  Passwords longer than 72 bytes are rejected because bcrypt ignores the remainder; passwords
  containing whitespace or control characters are rejected as well.
- `PUT /api/v1/users/{id}` preserves `is_active` when omitted; explicit `false` disables the
  account. Password/role changes and disabling revoke existing sessions.
- `security.token.refresh_method` must currently match `access_method`; access and refresh
  tokens share the same signing algorithm and key.

## Tests

```bash
go test ./...
go test -race ./...
go vet ./...
```
