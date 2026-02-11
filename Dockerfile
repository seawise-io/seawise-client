# Build stage
FROM golang:1.24-alpine AS builder

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
    mv /tmp/frp_${FRP_VERSION}_linux_${TARGETARCH}/frpc /frpc

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

# Run as non-root user for security (HIGH-13)
RUN addgroup -S seawise && adduser -S seawise -G seawise

WORKDIR /app

COPY --from=builder /seawise-client /app/seawise-client
COPY --from=frp-downloader /frpc /app/frpc

# Create directories for config and declare volume for persistence
RUN mkdir -p /home/seawise/.seawise && chown -R seawise:seawise /home/seawise/.seawise /app
VOLUME ["/home/seawise/.seawise"]

# Bind to all interfaces inside the container (overrides the localhost default in server.go)
ENV SEAWISE_BIND_ADDR=0.0.0.0

USER seawise

# Expose web UI port
EXPOSE 8082

ENTRYPOINT ["/app/seawise-client"]
