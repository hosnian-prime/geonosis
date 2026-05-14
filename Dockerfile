# Multi-stage container image for the `geonosis-server` binary.
#
# Per docs/11-deployment-k8s.md we ship a single static-ish binary;
# the runtime layer is a minimal debian-slim with just the certs and
# tzdata the OIDC / SAML / federation paths need at runtime. No JVM,
# no python, no shell tooling.
#
# Build:
#   docker build -t ghcr.io/hosnian-prime/geonosis-server:0.1.0 .
#
# Run:
#   docker run --rm -p 8080:8080 \
#     -e GEONOSIS_LISTEN=0.0.0.0:8080 \
#     -e GEONOSIS_DATABASE_URL=postgres://geonosis:pw@db/geonosis \
#     ghcr.io/hosnian-prime/geonosis-server:0.1.0
#
# The image is debug-symbol-stripped via `strip = "symbols"` in
# release; further size reductions (UPX, jemalloc swap) land in v0.2
# alongside the perf-tuning pass.

# ---- builder ------------------------------------------------------
FROM rust:1.86-slim-bookworm AS builder

WORKDIR /src

# Build deps. `pkg-config` + `libssl-dev` cover the few crates still on
# OpenSSL (`josekit`, `oauth2`); when we collapse to rustls everywhere
# in v0.2 these become unnecessary.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# Build the server binary in release mode. We don't `cargo chef` the
# layer cache here because the workspace is large enough that chef's
# planner step is its own cost — release pipelines should set a build
# cache mount instead.
RUN cargo build --release --bin geonosis-server

# ---- runtime ------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Non-root user, no shell access.
RUN groupadd --system --gid 65532 geonosis \
 && useradd  --system --uid 65532 --gid geonosis --no-create-home \
        --shell /sbin/nologin geonosis

# Trust roots + tzdata. Curl is bundled so the K8s `preStop` lifecycle
# hook can call `/-/drain` over loopback without an extra base layer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates tzdata curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/geonosis-server /usr/local/bin/geonosis-server

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/geonosis-server"]
