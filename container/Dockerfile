# The digest is a multi-platform index. `--platform linux/amd64` or `linux/arm64`
# selects the manifest. Renovate may propose a new digest; dependency locks and smoke
# tests must be reviewed.
FROM docker.io/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS runtime
COPY packages.lock /tmp/packages.lock
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive xargs -r -a /tmp/packages.lock apt-get install -y --no-install-recommends
COPY rcp /usr/local/bin/rcp
COPY LICENSE THIRD_PARTY_LICENSES.txt /usr/share/rcp/
COPY runtime-rootfs.py /tmp/runtime-rootfs.py
RUN chmod 0755 /usr/local/bin/rcp && python3 /tmp/runtime-rootfs.py /rootfs

FROM scratch
COPY --from=runtime /rootfs/ /
ARG RCP_VERSION=unknown
ARG RCP_SOURCE_REVISION=unknown
ARG RCP_BINARY_SHA256=unknown
LABEL org.opencontainers.image.title="rcp hardened runtime" \
      org.opencontainers.image.source="https://github.com/rust-cp/rcp" \
      org.opencontainers.image.version="$RCP_VERSION" \
      org.opencontainers.image.revision="$RCP_SOURCE_REVISION" \
      io.github.rust-cp.rcp.binary.sha256="$RCP_BINARY_SHA256"
ENV HOME=/state XDG_STATE_HOME=/state RCP_CATALOG=/state/catalog
USER 10001:10001
WORKDIR /state
ENTRYPOINT ["/usr/local/bin/rcp"]
CMD ["help"]
