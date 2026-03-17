# Build stage — pinned to digest for reproducible builds
FROM golang:1.26-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy dependency files first for caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary with version injection
ARG VERSION=dev
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X github.com/seawise/client/internal/constants.Version=${VERSION}" \
    -o /seawise-client ./cmd/seawise

# FRP client download stage (with checksum verification)
FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709 AS frp-downloader
ARG FRP_VERSION=0.67.0
ARG TARGETARCH=amd64
# SHA-256 checksums from https://github.com/fatedier/frp/releases/tag/v0.67.0
ARG FRP_SHA256_AMD64=f8629ca7ca56b8e7e7a9903779b8d5c47c56ad1b75b99b2d7138477acc4c7105
ARG FRP_SHA256_ARM64=0e9683226acdcbbb2ac8d073f35ba8be2a8b1e7584684d2073f39d337ebd6de7
RUN apk add --no-cache curl tar && \
    FRP_TARBALL="frp_${FRP_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl -Lo "/tmp/${FRP_TARBALL}" "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${FRP_TARBALL}" && \
    if [ "${TARGETARCH}" = "amd64" ]; then EXPECTED="${FRP_SHA256_AMD64}"; else EXPECTED="${FRP_SHA256_ARM64}"; fi && \
    echo "${EXPECTED}  /tmp/${FRP_TARBALL}" | sha256sum -c - && \
    tar -xzf "/tmp/${FRP_TARBALL}" -C /tmp && \
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/frpc /frpc && \
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/LICENSE /frp-LICENSE

# Runtime stage
FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709

RUN apk add --no-cache ca-certificates su-exec

# Create default user (entrypoint will adjust UID/GID to match PUID/PGID)
RUN addgroup -S seawise && adduser -S seawise -G seawise

WORKDIR /app

COPY --from=builder /seawise-client /app/seawise-client
COPY --from=frp-downloader /frpc /app/frpc

# FRP is Apache 2.0 licensed — include LICENSE for compliance
COPY --from=frp-downloader /frp-LICENSE /app/licenses/frp-LICENSE
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# /config is the standard mount point (like Overseerr, Sonarr, etc.)
RUN mkdir -p /config && chown seawise:seawise /config /app
VOLUME ["/config"]

# Bind to all interfaces inside the container
ENV SEAWISE_BIND_ADDR=0.0.0.0
# Tell the app to store data in /config (instead of ~/.seawise)
ENV SEAWISE_DATA_DIR=/config

# Expose web UI port
EXPOSE 8082

# Health check for Docker/Portainer/Watchtower container health reporting
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --spider -q http://localhost:8082/api/status || exit 1

# Entrypoint handles PUID/PGID, then drops to non-root user
ENTRYPOINT ["/app/entrypoint.sh"]
