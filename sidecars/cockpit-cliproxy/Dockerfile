FROM golang:1.26.0-alpine AS build

WORKDIR /src
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/cockpit-cliproxy .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -S -g 10001 cockpit \
    && adduser -S -D -H -u 10001 -G cockpit cockpit \
    && mkdir -p /data/auth \
    && chown -R 10001:10001 /data

WORKDIR /data
COPY --from=build /out/cockpit-cliproxy /usr/local/bin/cockpit-cliproxy

USER 10001:10001
EXPOSE 8317
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8317/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/cockpit-cliproxy"]
CMD ["--config", "/data/config.yaml", "--manifest", "/data/manifest.json", "--quota-reserve-state", "/data/quota-reserve.json", "--quota-pool-state", "/data/quota-pool.json"]
