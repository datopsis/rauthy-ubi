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

## FIDO metadata acquisition

The MDS snapshot is now authenticated independently of upstream's transformer.
`scripts/fido_mds.py` verifies RS256 (RSA PKCS#1 v1.5/SHA-256), the signing key,
RFC5280 certificate path and validity at verification time, and authenticated,
current CRLs for the leaf and intermediate. Trust is exclusively the checked-in
SHA-256-pinned GlobalSign Root R46 documented by FIDO; system trust is disabled.
The leaf must be a non-CA with digitalSignature usage and match
`mds.fidoalliance.org`. A lower serial, changed bytes at the same serial, malformed
or expired `nextUpdate`, unsupported algorithm/header, or missing/stale/invalid
CRL fails closed. Acquisition and the network-disabled build use the same code;
the build uses the already hash-locked OpenSSL/Python RPMs. No dependency was added.

See [acquisition](docs/ARTIFACT-ACQUISITION.md#fido-mds-verification-and-refresh)
for specification references and maintenance. This authenticates the published
snapshot; it does not independently validate vendor assertions, authenticator
attestation roots/revocation or runtime attestation decisions. No OCSP check is
made: revocation uses CRLs. Trust-anchor revocation is an owner-reviewed pin
change, not an automatic network trust update. This is not full production
qualification of FIDO metadata freshness or attestation policy.
