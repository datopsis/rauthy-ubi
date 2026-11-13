# Artifact acquisition

Release discovery on 2026-11-13 used GitHub's releases/latest and git/ref/tags APIs:
v0.37.2 resolves to fe6bcb95192e8a83c29e2b525bf4960933bea3bd. Fetches use the commit
archive URL and verify a recorded SHA-256; this is integrity pinning, not a publisher
signature. Rust hashes come from channel-rust-1.95.0.toml; Node hashes from its
SHASUMS256.txt; wasm-bindgen hashes from GitHub release asset metadata.

Runtime RPMs were resolved with weak dependencies disabled against UBI 9 BaseOS,
AppStream, and CodeReady Builder, per architecture. NEVRAs and hashes are recorded
in each lock. The image builder checks checksums, queries exact RPM identities,
and verifies Red Hat signatures before installation. No other repository is
allowed in the vulnerability availability query. Base OCI indexes are pinned by
digest. The same builder repository configuration is captured before installing
query tools for the vulnerability gate.

Lock updates are code changes: regenerate both architectures, inspect upstream
release/security notes, verify tag/commit association and all checksums, run the
full native workflow. Do not handwave unavailable artifacts or replace hashes to
make downloads pass. Build-stage RPMs are separately locked and checksum/signature verified.
The repository resolver is an explicit maintenance operation, never part of builds.

Borrowed security gate and tests come from datopsis/postgresql-lakekeeper-ubi.
The gate records vendor-fixed RPM findings deferred for lack of a UBI fix and keeps
unfixed findings in full reports. Deferral is a repository availability result,
not an exemption or exploitability judgment. Missing scanner reports fail closed.
