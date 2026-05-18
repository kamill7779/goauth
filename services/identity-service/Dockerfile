# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.2

FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/identity-service ./cmd/server

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S identity \
    && adduser -S -G identity identity

WORKDIR /app

COPY --from=builder /out/identity-service /app/identity-service
RUN mkdir -p /app/data/avatars && chown -R identity:identity /app/data

USER identity
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/readyz >/dev/null || exit 1

ENTRYPOINT ["/app/identity-service"]
