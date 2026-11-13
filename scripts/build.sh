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
docker build --file Containerfile --tag "${TEST_IMAGE:-rauthy-ubi:test}" \
    --build-arg UBI_BUILDER="${builder}" --build-arg UBI_RUNTIME="${runtime}" \
    --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
    --build-arg LOCK_SHA256="$(sha256sum "${lock}" | cut -d' ' -f1)" .
