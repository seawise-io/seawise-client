# Build stage — use latest 1.26 patch for security fixes
FROM golang:1.26-alpine AS builder

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
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS frp-downloader
ARG FRP_VERSION=0.68.1
ARG TARGETARCH=amd64
# SHA-256 checksums from https://github.com/fatedier/frp/releases/download/v0.68.1/frp_sha256_checksums.txt
ARG FRP_SHA256_AMD64=4a4e88987d39561e1b3b3b23d0ede48a457eebf76a87231999957e870f5f02b6
ARG FRP_SHA256_ARM64=e7ad15b0cfe4cf0125df4217778b66cb4426179270967b59900ecb2362d8cd01
RUN apk add --no-cache curl tar && \
    FRP_TARBALL="frp_${FRP_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl -Lo "/tmp/${FRP_TARBALL}" "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${FRP_TARBALL}" && \
    if [ "${TARGETARCH}" = "amd64" ]; then EXPECTED="${FRP_SHA256_AMD64}"; else EXPECTED="${FRP_SHA256_ARM64}"; fi && \
    echo "${EXPECTED}  /tmp/${FRP_TARBALL}" | sha256sum -c - && \
    tar -xzf "/tmp/${FRP_TARBALL}" -C /tmp && \
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/frpc /frpc && \
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/LICENSE /frp-LICENSE

# Runtime stage
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

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
