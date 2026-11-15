# Changelog

## Unreleased

- Initial UBI 9 Rauthy 0.37.2 source-build profile for amd64 and arm64.
- Mandatory verified TLS, mounted secrets, non-root runtime, PostgreSQL persistence.
- Native OIDC/PKCE, hardening and negative TLS tests; independent vulnerability gates.
- Architecture-specific artifact locks and checked provenance labels.
- Rust scanned from the cargo-auditable crate list embedded in the binary; installed
  npm package manifests retained so Trivy and Grype both see the frontend inventory.
- Native PostgreSQL fixture provisions a least-privileged `rauthy` role and database.
