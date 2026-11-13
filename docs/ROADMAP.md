# Roadmap

1. Qualify the first single-node PostgreSQL profile on both native architectures.
   Close every blocking scanner finding; request upstream dependency fixes without
   silently editing Cargo.lock or package-lock.json. Prove clean-room bit reproducibility and archive acquired bundles.
2. HA: validate upstream Hiqlite/Raft cache with 3/5 nodes, private authenticated
   TLS, unique durable node volumes, quorum loss, partitions, failover and recovery.
   External PostgreSQL alone does not make Rauthy stateless. Embedded database
   mode remains test-only here until a supported HA/recovery story is demonstrated.
3. Backup/restore: PostgreSQL consistent snapshots/PITR, encryption-key escrow,
   configuration and cache state recovery, disaster recovery exercises and measured
   RPO/RTO. A database backup without encryption keys is insufficient.
4. Upgrades: read every intervening release's breaking changes, rehearse schema
   migrations on restored production-shaped data, establish forward recovery and
   rollback limits, and test old/new clients. Rauthy 0.35 changed the issuer to
   include a trailing slash: treat exact issuer matching as a compatibility
   contract, not a URL normalization detail. Never edit consumers silently.
5. Signing-key rotation: exercise JWKS overlap, cache refresh, old/new-token
   validity windows, revoked/expired keys and emergency rotation. Separately test
   database encryption-key rotation and recovery of data encrypted with old keys.
6. Operational qualification: load, resource exhaustion, revocation/logout,
   passkeys/MFA enrollment, SMTP, certificate renewal, audit logging and alerting.
   Evaluate minimal shell-free runtime and cryptographic/FIPS claims with evidence.
