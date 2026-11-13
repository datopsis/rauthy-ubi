#!/usr/bin/env bash
set -Eeuo pipefail
case "$(uname -m)" in
    x86_64) architecture=amd64 ;;
    aarch64) architecture=arm64 ;;
    *) exit 1 ;;
esac
lock="artifacts/locks/${architecture}.json"
python3 scripts/artifacts.py acquire "${lock}" --output .artifact-bundle
builder=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_images"]["builder"]["reference"])' "${lock}")
runtime=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_images"]["runtime"]["reference"])' "${lock}")
if test "${PREPARE_ONLY:-false}" = true; then
    {
        printf 'builder=%s\n' "${builder}"
        printf 'runtime=%s\n' "${runtime}"
        printf 'revision=%s\n' "$(git rev-parse HEAD)"
        printf 'lock_sha256=%s\n' "$(sha256sum "${lock}" | cut -d' ' -f1)"
    } >> "${GITHUB_OUTPUT:?}"
    exit 0
fi
docker build --file Containerfile --tag "${TEST_IMAGE:-rauthy-ubi:test}" \
    --build-arg UBI_BUILDER="${builder}" --build-arg UBI_RUNTIME="${runtime}" \
    --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
    --build-arg LOCK_SHA256="$(sha256sum "${lock}" | cut -d' ' -f1)" .
