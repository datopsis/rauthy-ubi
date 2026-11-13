# syntax=docker/dockerfile:1.7
ARG UBI_BUILDER
ARG UBI_RUNTIME
FROM ${UBI_BUILDER} AS acquire
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY .artifact-bundle/ /bundle/
WORKDIR /bundle
RUN sha256sum --check SHA256SUMS \
    && rpmkeys --checksig build-rpms/*.rpm \
    && rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' build-rpms/*.rpm | sort > /build-nevras \
    && test "$(cat BUILD-NEVRAS)" = "$(cat /build-nevras)" \
    && rpm --upgrade --replacepkgs build-rpms/*.rpm \
    && mkdir /src /toolchain /node /wasm-tools \
    && tar -xf source.tar.gz -C /src --strip-components=1 \
    && tar -xf rust.tar.xz -C /toolchain --strip-components=1 \
    && /toolchain/install.sh --prefix=/usr/local --without=rust-docs --disable-ldconfig \
    && rm -rf /toolchain \
    && mkdir /toolchain \
    && tar -xf rust-wasm.tar.xz -C /toolchain --strip-components=1 \
    && /toolchain/install.sh --prefix=/usr/local --disable-ldconfig \
    && tar -xf node.tar.xz -C /node --strip-components=1 \
    && tar -xf wasm-bindgen.tar.gz -C /wasm-tools --strip-components=1
ENV PATH="/node/bin:/wasm-tools:/usr/local/bin:/usr/bin:/bin" CARGO_BUILD_JOBS=2 CARGO_HOME=/cargo OPENSSL_NO_VENDOR=1
WORKDIR /src
RUN test "$(node --version)" = "v22.23.5" \
    && test "$(npm --version)" = "10.9.9" \
    && rustc --version | grep -F "rustc 1.95.0 " \
    && sha256sum Cargo.lock frontend/package-lock.json > /upstream-locks.sha256 \
    && cargo fetch --locked \
    && npm --prefix frontend ci --ignore-scripts --no-audit --no-fund \
    && rm -rf frontend/node_modules

FROM acquire AS build
COPY scripts/build-source.sh /build-source.sh
RUN --network=none bash /build-source.sh

FROM acquire AS launcher
COPY container/launcher.rs /launcher.rs
RUN --network=none rustc --edition 2024 -C opt-level=2 -C strip=symbols /launcher.rs -o /launcher

FROM ${UBI_RUNTIME} AS micro
FROM acquire AS runtime-root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY --from=micro / /runtime/
WORKDIR /bundle
RUN sha256sum --check SHA256SUMS \
    && rpmkeys --checksig rpms/*.rpm \
    && rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' rpms/*.rpm | sort > /actual-nevras \
    && diff -u NEVRAS /actual-nevras \
    && rpm --root /runtime --upgrade --replacepkgs rpms/*.rpm \
    && mkdir -p /runtime/data /runtime/bootstrap /runtime/run/secrets /runtime/etc/rauthy \
    && chown 10001:10001 /runtime/data \
    && find /runtime -xdev -type f -perm /6000 -exec chmod a-s '{}' + \
    && rm -rf /runtime/var/cache/* /runtime/var/log/* /runtime/tmp/*

FROM ${UBI_RUNTIME}
ARG SOURCE_REVISION
ARG LOCK_SHA256
LABEL org.opencontainers.image.title="Rauthy on Red Hat UBI 9" \
      org.opencontainers.image.source="https://github.com/datopsis/rauthy-ubi" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.37.2" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.datopsis.artifact-lock.sha256="${LOCK_SHA256}" \
      io.datopsis.rauthy.upstream-revision="fe6bcb95192e8a83c29e2b525bf4960933bea3bd"
COPY --from=runtime-root /runtime/ /
COPY --from=build --chmod=0555 /src/target/release/rauthy /usr/local/bin/rauthy
COPY --from=launcher --chmod=0555 /launcher /usr/local/bin/rauthy-launcher
# Source inventories deliberately retained so scanners can see Rust and bundled JS.
# They are declared dependency graphs, not a claim that all optional crates shipped.
COPY --from=build /src/Cargo.lock /usr/share/rauthy/Cargo.lock
COPY --from=build /src/frontend/package-lock.json /usr/share/rauthy/frontend/package-lock.json
COPY container/production.toml /etc/rauthy/production.toml
WORKDIR /data
USER 10001:10001
EXPOSE 8443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/rauthy-launcher"]
