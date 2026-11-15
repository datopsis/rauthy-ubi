# Security policy

This initial image is under qualification. Only the pinned release and enforced
single-node PostgreSQL/TLS profile are in scope; no production support SLA or FIPS
certification is promised. Report vulnerabilities through the repository's private
GitHub vulnerability reporting channel when available, or upstream Rauthy's security
contact. Never put tokens, passwords, keys or identifying production logs in issues.

Both Trivy and Grype must execute successfully. Fixable High/Critical findings
block: UBI-installable RPM fixes, every fixed non-RPM finding, and repository query
errors. There are no exemptions or suppression files. Unfixed/deferred findings
remain visible and must be monitored. Rust findings come from the binary's embedded
cargo-auditable crate list, so build-only crates (for example the `zip` used by the
utoipa-swagger-ui build script) are outside the image scan. The JS inventory
conservatively includes development tooling.

## Build-time dependency audit (non-blocking)

The separate `build-time dependencies` CI job keeps build-time findings visible
without changing the image gate. It Trivy-scans the full pinned upstream
`Cargo.lock` and `frontend/package-lock.json`, build and development dependencies
included. It lists every High/Critical finding whose package and version are in
neither architecture's shipped image inventory. Each finding shows its package,
version, fixed version, and the build step that uses it. Build steps come from
`cargo metadata` for linux amd64/arm64 and wasm32, and from the package-lock flags.
It also flags crates linked into the WASM modules: those ship inside the binary but
are not in its cargo-auditable list. The job never blocks a release. It errors if
the source, lockfile scan, Cargo graphs or image inventories are missing, or if
scan coverage is too low. Scheduled and manual runs on `main` comment on the
tracking issue "Build-time dependency vulnerabilities (scheduled tracking)" only
when the finding set changes. Pull requests preview that update read-only.
Do not modify upstream lockfiles without explicitly flagging the dependency change
for the owner. Do not relax TLS, runtime, or CI checks to make a release pass.
