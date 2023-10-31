# go backend builder
FROM golang:1.21 as gobuilder
ARG VERSION=development
WORKDIR /go/src/app
COPY . .
RUN go test ./...
RUN go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /pigdns ./cmd/server

# Final docker image
FROM debian:stable-slim
RUN set -eux; \
    apt update && \
    apt install -y \
        ca-certificates \
        psmisc \
        procps \
        netcat-openbsd \
        dnsutils \
    && \
    apt clean

RUN mkdir -p /var/lib/pigdns && mkdir -p /etc/pigdns

COPY --from=gobuilder /pigdns /usr/local/bin/pigdns
COPY ./default.yaml /etc/pigdns/pigdns.yaml

VOLUME /var/lib/pigdns

ENTRYPOINT ["/usr/local/bin/pigdns", "/etc/pigdns/pigdns.yaml"]