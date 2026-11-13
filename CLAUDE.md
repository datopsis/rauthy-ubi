# Repository guidance

Read README.md, SECURITY.md and docs/CONFIGURATION.md before changing the profile.
Keep the implementation aligned with datopsis/lakekeeper-ubi and
datopsis/postgresql-lakekeeper-ubi security conventions.

Never weaken assertions or scanner gates, introduce exemptions, disable certificate
verification, or change GitHub settings, permissions, secrets or branch protection.
No human sign-off gates. No AI or Co-Authored-By commit trailers. Never force-push
or merge without an explicit request. Pull/rebase before every push.

Use LF exclusively; run pre-commit and validate YAML before pushing. Required job
names are `lint`, `configuration security`, and aggregate `image`, which requires
both native image jobs. Never replace native arm64 validation with emulation.
Containers cannot run in the Cloudroom sandbox: use PR Actions and inspect actual
logs/artifacts. Report anything unverified and preserve red results honestly.

Do not patch upstream lockfiles silently. Pin version/tag/commit, toolchains,
checksums and runtime RPM NEVRA/SHA-256 for each architecture. Maintain the exact
revision and lock-digest label checks. Never commit private test material or upload
raw logs containing secrets. Preserve acquisition trust and support limitations.
