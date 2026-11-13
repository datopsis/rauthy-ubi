# Rauthy on Red Hat UBI 9

First increment of Datopsis's Phase B OpenID Connect provider. Rauthy **0.37.2**
is built from source, including its frontend and WASM modules, natively on amd64
and arm64. This is a qualification candidate, not a production qualification claim.
See [validation evidence](docs/VALIDATION.md) for the actual results and limits.

## Support contract

Supported profile: one Rauthy instance, HTTPS on 8443, mounted certificates and
secrets, external PostgreSQL with verified TLS, persistent `/data` for Hiqlite's
cache, non-root UID/GID 10001, read-only root, no capabilities, and
no-new-privileges. Bootstrap uses upstream declarative JSON. Identity data lives
in PostgreSQL; cache persistence is still required. Admin MFA remains enabled.

Embedded Hiqlite identity storage is **test-only**, outside this image's enforced
production profile. Upstream documents Raft HA, but this repository has not proved
multi-node availability, partitions, recovery, or upgrades. HA, automatic migration
rollback, FIPS certification, SCAP compliance, production backup/restore and
unrestricted upstream configuration are not supported by this increment.
No claim is made that the image or dependencies are vulnerability-free.

## Build

Use Docker/BuildKit on the native architecture:

```sh
TEST_IMAGE=rauthy-ubi:test bash scripts/build.sh
```

`artifacts/locks/{amd64,arm64}.json` pins the source tag and commit, source SHA-256,
Rust 1.95.0, Node 22.23.5 (bundled npm), wasm-bindgen 0.2.129, UBI image digests,
and runtime RPM NEVRAs and SHA-256. Acquisition verifies downloads; Rust uses
`cargo fetch --locked` followed by `cargo build --frozen`; npm uses the unchanged
upstream package-lock for acquisition and `npm ci --offline` in a network-disabled
build stage. No upstream lockfile is patched. The FIDO metadata is the release's
committed dataset; refreshing it is a separate upstream operation.

Build-stage and runtime RPM closures are separately locked. Dependency acquisition
is online; compilation is network-disabled. Bit reproducibility is not yet proved. Source tarball checksums
are recorded locally over HTTPS, not an upstream signature. Toolchain checksums
come from the publishers' release metadata. See [artifact acquisition](docs/ARTIFACT-ACQUISITION.md).

## Runtime

See [configuration](docs/CONFIGURATION.md) for the exact mount and environment
contract. Never expose ports 8100/8200 publicly: the internal cache uses TLS on
both. No HTTP, redirect, or metrics listener is enabled. The compiled launcher
ignores arbitrary upstream environment overrides and requires every secret before
starting. Root filesystem and capability restrictions must also be supplied by
the container orchestrator; image metadata alone cannot enforce those flags.

```sh
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  --pids-limit=256 --memory=2g --cpus=2 \
  --tmpfs=/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001 \
  -v /srv/rauthy/data:/data:rw \
  -v /srv/rauthy/secrets:/run/secrets:ro \
  -v /srv/rauthy/bootstrap:/bootstrap:ro \
  --env-file /srv/rauthy/nonsecret.env \
  -p 8443:8443 rauthy-ubi:test
```

A shell is not needed by the entrypoint. UBI RPM scriptlet dependencies may retain
a shell in the runtime closure; this is not advertised as a shell-free image.
Do not mount configuration over the enforced profile or override the entrypoint.
Such changes leave this support contract.

## Security and CI

Required checks are exactly `lint`, `configuration security`, and `image`.
The aggregate requires **both** `image (amd64)` and `image (arm64)`.
Every native job builds the pinned datopsis/postgresql-ubi source, checks both
images' revision and lock labels, and runs identical assertions with fresh PKI.
Trivy and Grype independently block fixable High/Critical findings. An RPM vendor
fix is actionable only when it is available from the native UBI repositories;
query errors block. Non-RPM fixes always block. No exemption lists are accepted.
Full scanner JSON, sanitized assertions, SPDX, provenance and sizes are retained
as CI artifacts. Source dependency inventories are conservative graphs, not proof
that every optional crate or npm development package is in the executable.

Install pre-commit using `.github/requirements/pre-commit.txt`, then run
`pre-commit install --install-hooks`. All text uses LF. See [SECURITY.md](SECURITY.md)
and [roadmap](docs/ROADMAP.md).
