# Build stage
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

# FRP client download stage
FROM alpine:3.21 AS frp-downloader
ARG FRP_VERSION=0.67.0
ARG TARGETARCH=amd64
RUN apk add --no-cache curl tar && \
    curl -L "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${TARGETARCH}.tar.gz" | \
    tar -xz -C /tmp && \
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/frpc /frpc && \
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/LICENSE /frp-LICENSE

# Runtime stage
FROM alpine:3.21

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

# Entrypoint handles PUID/PGID, then drops to non-root user
ENTRYPOINT ["/app/entrypoint.sh"]
