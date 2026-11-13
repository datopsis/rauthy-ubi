# Production configuration

The fixed `container/production.toml` is the only supported server configuration.
No CLI arguments are accepted. The launcher clears inherited environment variables,
then passes the following required nonsecret values: `PUB_URL` (host:port without
scheme), `RP_ID` (hostname), `RP_ORIGIN` (HTTPS origin), `PG_HOST`, `PG_USER`,
`PG_DB_NAME`, `BOOTSTRAP_ADMIN_EMAIL`. Optional `PG_PORT` defaults to 5432.
Configure DNS and issuer carefully before initial bootstrap.

Mount `/run/secrets` read-only, readable by UID 10001. Required nonempty files:

| File | Meaning |
| --- | --- |
| server.crt, server.key | PEM leaf chain and key for HTTPS and internal cache TLS |
| ca.crt | Trust for cache peers and outbound HTTPS; certificate must cover localhost |
| pg-ca.crt | Explicit PostgreSQL CA bundle, independently configurable |
| pg-password | PostgreSQL password |
| encryption-keys | Upstream `ENC_KEYS` format: newline-separated `id/base64-32-byte-key` |
| encryption-key-active | Active ID present in encryption-keys |
| raft-secret, api-secret | Independent random cache authentication secrets |
| admin-password-argon2id | Prehashed initial administrator password |

Generate secrets with a cryptographic random generator and manage them externally.
Never copy evaluation passwords, embed secrets in images, or publish raw logs.
The launcher only reports the missing file's name. Upstream parses and validates
keys and certificates. Blank or unreadable files stop startup before listeners.
An invalid certificate must fail TLS validation at the client.

Mount bootstrap JSON at `/bootstrap` read-only. Upstream recognizes `clients.json`,
`users.json`, `groups.json`, `roles.json`, `scopes.json`, `user_attributes.json`, and
`api_keys.json`. The upstream release's
[types](https://github.com/sebadob/rauthy/blob/v0.37.2/src/data/src/migration/bootstrap/types.rs)
are the schema. A client without a secret is public and uses S256 PKCE; a machine
client needs an independent 64-character secret and the `client_credentials` flow.
Include `groups` in scopes for human group claims. Machine tokens have a mapped
subject but do not inherit human groups. Bootstrap is initial provisioning, not
ongoing drift reconciliation. Retain required mounted secrets across restarts.

Only `/data` (persistent, owned by 10001) and `/tmp` (bounded tmpfs) are writable.
Allow 40 seconds for graceful shutdown. Do not share `/data` between replicas.
Internal TLS ports 8100/8200 must stay on a private network; this increment is
single-node only. Public TLS on 8443 uses the configured public hostname.

## PostgreSQL verify-full semantics

Rauthy 0.37.2 does **not** accept libpq's literal `sslmode=verify-full` value.
Its equivalent is `pg_tls='require'`, `pg_tls_no_verify=false`, and `pg_tls_root_ca`
loaded from the mounted CA. The upstream tokio-postgres Rustls connector verifies
the certificate chain and hostname, with no plaintext fallback. Passing the literal
`verify-full` to `PG_TLS` would panic. Native tests must prove wrong CA and wrong
hostname rejection; this translation is never treated as permission to disable
verification. Production PostgreSQL must independently enforce hostssl/SCRAM.

The native fixture builds datopsis/postgresql-ubi at the exact main commit in
`artifacts/postgresql.commit`. Recheck the pin before upgrades. Back up PostgreSQL,
encryption keys, configuration and cache state together; restore qualification is
still a roadmap item.
