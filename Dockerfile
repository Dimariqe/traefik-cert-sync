# Cross-compiles a static musl binary on the build host (no QEMU needed for
# compilation) for linux/amd64, linux/arm64 and linux/arm/v7.
FROM --platform=$BUILDPLATFORM rust:1-alpine AS builder

ARG TARGETPLATFORM

RUN \
    case "$TARGETPLATFORM" in \
      linux/amd64)  RUST_TARGET=x86_64-unknown-linux-musl ;; \
      linux/arm64)  RUST_TARGET=aarch64-unknown-linux-musl ;; \
      linux/arm/v7) RUST_TARGET=armv7-unknown-linux-musleabihf ;; \
      *) echo "unsupported TARGETPLATFORM $TARGETPLATFORM" >&2; exit 1 ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    echo "$RUST_TARGET" > /rust-target

COPY . /src
WORKDIR /src

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/src/target \
    RUST_TARGET=$(cat /rust-target) && \
    cargo build --release --locked --target "$RUST_TARGET" && \
    cp "target/$RUST_TARGET/release/traefik-cert-sync" /traefik-cert-sync

FROM alpine:3.24.2

# openssl CLI backs the optional COMBINE_PKCS12 / CONVERT_KEYS_TO_RSA steps.
# Container/service restarts talk to the Docker Engine API over the mounted
# socket directly, so no Docker installation is needed in the image.
RUN \
    apk update && \
    apk add --no-cache \
        --no-progress \
        openssl \
        ca-certificates \
        tzdata && \
    rm -rf /var/cache/apk/*

COPY --from=builder /traefik-cert-sync /usr/bin/traefik-cert-sync

HEALTHCHECK --interval=30s --timeout=10s --retries=5 \
  CMD ["/usr/bin/traefik-cert-sync", "--healthcheck"]

VOLUME ["/traefik"]
VOLUME ["/output"]

ENTRYPOINT ["/usr/bin/traefik-cert-sync"]
