# Build stage
FROM rust:1.92-slim AS builder

WORKDIR /build
COPY . .

RUN apt-get update && apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage — minimal image
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rdhcpd /rdhcpd

# Default config location
VOLUME ["/etc/rdhcpd", "/var/lib/rdhcpd"]

# DHCPv4, DHCPv6, API
EXPOSE 67/udp 547/udp 8080/tcp

ENTRYPOINT ["/rdhcpd"]
CMD ["/etc/rdhcpd/config.toml"]
