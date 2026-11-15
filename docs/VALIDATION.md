# Validation evidence

Native GitHub Actions run 43730269603 (PR #1, commit e19d4b5) on `ubuntu-24.04`
(amd64) and `ubuntu-24.04-arm` (arm64). No emulation. No container execution was
performed in the development sandbox. Every required check passed: `lint`,
`configuration security`, `image (amd64)`, `image (arm64)`, aggregate `image`.

## Functional and negative tests (both architectures: PASS)

HTTPS readiness; declarative administrator bootstrap persisted in PostgreSQL; OIDC
discovery and JWKS over verified TLS; confidential client credentials with iss/aud/
exp and JWKS signature checks; public S256 PKCE with groups in the signed token;
plaintext, wrong-CA and wrong-hostname refusal on 8443/8100/8200; UID 10001,
read-only root, CapEff 0, NoNewPrivs, only `/data` (bind) and `/tmp` (tmpfs,
noexec, nosuid) writable with read-only secret and bootstrap mounts; PostgreSQL
restart persistence; PostgreSQL wrong CA and wrong hostname refused; each missing
secret fails closed; expired server certificate refused with restored control.

The PostgreSQL rejection proof is differential: tokio-postgres reports only "error
performing TLS handshake" and PostgreSQL logs only an EOF. Each case changes one
input (the CA file, or a hostname alias of the same server). Rauthy must exit
non-zero with that handshake error and no listener. The unchanged profile must
then become ready again.

The fixture runs PostgreSQL with a `postgres` superuser and provisions a
non-superuser `rauthy` role that owns database `rauthy`; PUBLIC has no database
privileges. Rauthy creates its schema through upstream migrations.

## Scanner coverage and gate

| Arch | Trivy redhat / rustbinary / node-pkg | Syft rpm / cargo / npm |
| --- | --- | --- |
| amd64 | 40 / 575 / 173 | 40 / 575 / 173 |
| arm64 | 40 / 574 / 173 | 40 / 574 / 173 |

High/Critical: 0 for both scanners on both architectures, so 0 blocked and
0 deferred. Remaining findings (identical per arch), all recorded in the full
reports: Trivy RPM 7 Medium + 20 Low unfixed; Trivy npm 4 Medium + 3 Low with a
fix. Grype RPM 7 Medium + 20 Low not fixed or won't fix; Grype npm 4 Medium +
3 Low fixed, 1 Low not fixed. The npm findings are in the conservative
frontend inventory, which includes development tooling.

## Build-time dependency audit

Separate from the gate above and non-blocking. The `build-time dependencies` job
scans the full upstream lockfiles. It reports High/Critical findings absent from
both shipped inventories, with build-step attribution. Results are in the job
summary and the `build-time-audit-<sha>` artifact. Scheduled runs on `main` update
the tracking issue. Missing inputs or insufficient lockfile coverage make the job
error, never report clean. Known build-time finding when introduced: `zip` 3.0.0
(CVE-2026-115905 Critical, CVE-2026-115909 High), a build-dependency of
utoipa-swagger-ui.

## Limits

Image sizes: amd64 130.8 MB, arm64 123.5 MB. Bit reproducibility, HA, upgrades
and backup/restore are not validated. Build-only Rust crates are outside the
binary scan; upstream Cargo.lock still pins `zip` 3.0.0, used only by the
utoipa-swagger-ui build script.
