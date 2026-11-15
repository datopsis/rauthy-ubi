#!/usr/bin/env bash
set -Eeuo pipefail
cd /src
if test "$(uname -m)" = aarch64; then
    export JEMALLOC_SYS_WITH_LG_PAGE=16
fi
# No resolver or network is available in this build stage.
cargo install --frozen --path /cargo-auditable --root /usr/local
test -x /usr/local/bin/cargo-auditable
npm --prefix frontend ci --offline --ignore-scripts --no-audit --no-fund
for feature in spow md; do
    cargo build --frozen --release -p rauthy-wasm-modules --target wasm32-unknown-unknown --features "${feature}"
    mkdir -p "frontend/src/wasm/${feature}"
    wasm-bindgen target/wasm32-unknown-unknown/release/wasm.wasm \
        --target bundler --out-dir "frontend/src/wasm/${feature}" --out-name "${feature}"
done
mkdir -p templates/html static/v1
npm --prefix frontend run build
# Every package installed from the upstream lock keeps its package.json for scanners.
node - <<'JS'
const fs = require('fs');
const path = require('path');
const lock = JSON.parse(fs.readFileSync('frontend/package-lock.json', 'utf8'));
let copied = 0;
for (const entry of Object.keys(lock.packages)) {
    if (!entry.startsWith('node_modules/')) continue;
    const source = path.join('frontend', entry, 'package.json');
    if (!fs.existsSync(source)) continue; // optional package for another platform
    const target = path.join('/inventory/frontend', entry, 'package.json');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
    copied += 1;
}
if (copied < 100) throw new Error(`only ${copied} npm package manifests`);
console.log(`npm package manifests: ${copied}`);
JS
# Upstream deliberately permits a missing dataset ONLY to bootstrap this debug tool.
# The release build below still requires the real generated dataset. No bypass or placeholder.
CARGO_PROFILE_DEV_DEBUG=0 cargo run --frozen --bin fido-mds-prep -- \
    --source /bundle/fido-mds.jwt --out assets/fido_mds/dataset.bin
test -s assets/fido_mds/dataset.bin
rm -rf target/debug
# cargo-auditable embeds the exact linked dependency set for binary scanners.
cargo auditable build --frozen --release --bin rauthy
sha256sum --check /upstream-locks.sha256
