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
Do not modify upstream lockfiles without explicitly flagging the dependency change
for the owner. Do not relax TLS, runtime, or CI checks to make a release pass.
