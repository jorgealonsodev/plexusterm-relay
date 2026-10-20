# plexusterm-relay: relay + static web viewer in one small image.
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 -t plexusterm-relay .

# The viewer is plain JS/CSS, identical for every platform: build it once on
# the build host.
FROM --platform=$BUILDPLATFORM node:22-slim AS viewer
ARG VIEWER_BUILD_HASH=dev
WORKDIR /src/viewer
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
COPY viewer/package.json viewer/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY viewer/ ./
RUN VIEWER_BUILD_HASH=$VIEWER_BUILD_HASH pnpm exec vite build

# This toolchain is the crate's MSRV (rust-version in Cargo.toml).
FROM rust:1.92-slim-bookworm AS relay
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p plexusterm-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=relay /src/target/release/plexusterm-relay /usr/local/bin/plexusterm-relay
COPY --from=viewer /src/viewer/dist /app/viewer
ENV RELAY_LISTEN=0.0.0.0:8080 \
    VIEWER_LISTEN=0.0.0.0:8081 \
    VIEWER_DIR=/app/viewer
EXPOSE 8080 8081
USER nonroot
ENTRYPOINT ["/usr/local/bin/plexusterm-relay"]
