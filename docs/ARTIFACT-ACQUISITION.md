# Artifact acquisition

Release discovery on 2026-11-13 used GitHub's releases/latest and git/ref/tags APIs:
v0.37.2 resolves to fe6bcb95192e8a83c29e2b525bf4960933bea3bd. Fetches use the commit
archive URL and verify a recorded SHA-256; this is integrity pinning, not a publisher
signature. Rust hashes come from channel-rust-1.95.0.toml; Node hashes from its
SHASUMS256.txt; wasm-bindgen hashes from GitHub release asset metadata. The
cargo-auditable 0.7.7 crate hash is the crates.io registry checksum; its own
published Cargo.lock is fetched with `--locked` and built offline with `--frozen`.

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

## FIDO MDS verification and refresh

The source archive omits the required FIDO dataset. The separately pinned raw
JWT is verified by `scripts/fido_mds.py` before upstream's offline `fido-mds-prep`
transformation. The nonempty release dataset requirement remains enforced.

The verifier follows the [MDS3 processing rules, §3.2](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#metadata-blob-object-processing-rules)
and [payload/JOSE definitions, §§3.1.6–3.1.7](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#metadata-blob-payload-dictionary):

- Explicit RS256 allowlist and RSA key binding; verify the original compact JWS
  signing input with PKCS#1 v1.5/SHA-256. Reject other algorithms, `x5u`, critical
  extensions and unknown header fields rather than interpreting them partially.
- Verify the x5c RFC5280 path, certificate signatures, CA/path/key usage
  constraints, validity periods and signing hostname with OpenSSL strict mode.
  No system CA trust is used. `artifacts/fido-mds/root.pem` is the GlobalSign
  Root R46 documented on the [official FIDO MDS page](https://fidoalliance.org/metadata/).
  `trust.json` records its official download URL and DER SHA-256
  `4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9`.
  The cross-signed R46 supplied in x5c is untrusted input; the path terminates
  at the independently pinned self-signed R46.
- Fetch CRLs from the two reviewed HTTPS endpoints in `trust.json`, not from
  arbitrary JWT URLs. OpenSSL `-crl_check_all` verifies their signatures,
  issuers, validity and revocation status across the leaf/intermediate path.
  Missing, stale or invalid CRLs block. OCSP is not checked. The trust anchor's
  withdrawal/replacement requires an owner-reviewed pin change. An issuer or
  algorithm rotation may require reviewed verifier/configuration changes.
- Require a positive integer `no` at least as high as the current lock; reject
  same-serial content changes. Require ISO date `nextUpdate` strictly after
  today's UTC date (the deadline is UTC midnight). No grace period is allowed.

Acquisition checks SHA-256 and publisher verification, including fresh CRLs.
Those CRLs accompany the bundle; the build rechecks it using the hash-locked
OpenSSL/Python RPMs immediately before offline transformation. Old bundles stop
working when certificates, CRLs or `nextUpdate` expire; retaining bytes preserves
integrity evidence, not indefinite permission to consume stale metadata.
The maintenance/host checks use installed OpenSSL 3 and Python's standard library;
there is no new dependency. Upstream lockfiles are unchanged.

The verified refresh is serial **302**, `nextUpdate` **2026-12-01**, SHA-256
`d2ad4e42a8afbd74a34b3e997ae46d43df9e046f8a5bf1feda97206d8c84e0bb`.
`artifacts/fido-mds/refresh-evidence.json` records the verification time and
exact change from serial 301. This authenticates publisher bytes, not the truth
of vendor assertions, entry attestation roots/revocation, or runtime attestation
policy. Full production qualification remains outstanding.

To refresh both architecture locks only after all verification succeeds:

```sh
python3 scripts/fido_mds.py refresh --crl-dir /tmp/mds-crls --fetch-crls --output /tmp/mds-evidence.json
```

Review the lock diff and evidence, run lightweight tests/pre-commit, then submit
one PR for existing native amd64/arm64 Actions builds, scans and runtime tests.
A mutable feed change must still fail checksum acquisition until that refresh.

The daily/manual `FIDO MDS refresh tracking` workflow runs only on `main`, never
on pull requests. It uses the same verifier in read-only report mode, fails on
any verification error and only reports higher serials. With the default
GITHUB_TOKEN and job-scoped `issues: write`, it opens or updates one marked
tracking issue, reopening it if necessary, with verification evidence and the
exact lock patch. Workflow concurrency prevents duplicate creates. It never
writes a lock, creates a branch or opens a PR. PR-based automation would require
the repository setting **Allow GitHub Actions to create and approve pull requests**;
enabling that is an owner decision. No repository setting is changed here.
