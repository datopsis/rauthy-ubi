#!/usr/bin/env bash
set -Eeuo pipefail
commit=$(cat artifacts/postgresql.commit)
mkdir -p .test-work/postgresql
git -C .test-work/postgresql init -q
git -C .test-work/postgresql fetch --depth=1 https://github.com/datopsis/postgresql-ubi "${commit}"
git -C .test-work/postgresql checkout --detach FETCH_HEAD
test "$(git -C .test-work/postgresql rev-parse HEAD)" = "${commit}"
cd .test-work/postgresql
CONTAINER_RUNTIME=docker IMAGE=postgresql-ubi:test RELEASE_REVISION="${commit}" bash scripts/build-offline.sh
