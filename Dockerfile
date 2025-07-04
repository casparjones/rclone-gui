# -------- Build Stage --------
FROM rust:1.87-slim-bullseye AS builder

# Install musl toolchain & Co
RUN apt-get update && apt-get install -y \
    musl-tools \
    pkg-config \
    libssl-dev \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first
COPY Cargo.toml Cargo.lock ./

# Dummy main to cache deps
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Pre-build deps
RUN cargo build --release --target x86_64-unknown-linux-musl && \
    rm -rf target/x86_64-unknown-linux-musl/release/deps/rclone_gui*

# Copy real code
COPY src/ ./src/
COPY static/ ./static/

# Final build (musl statisch)
RUN cargo build --release --target x86_64-unknown-linux-musl

# Strip Binary
RUN strip target/x86_64-unknown-linux-musl/release/rclone-gui

# -------- Runtime Stage --------
FROM alpine:3.19

# Runtime-Tools installieren (ohne libc!)
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates wget unzip && \
    # Install rclone v1.70.1 directly from GitHub releases
    wget --retry-connrefused --tries=3 -O rclone.zip https://github.com/rclone/rclone/releases/download/v1.70.1/rclone-v1.70.1-linux-amd64.zip && \
    unzip rclone.zip && \
    mv rclone-v1.70.1-linux-amd64/rclone /usr/local/bin/ && \
    chmod +x /usr/local/bin/rclone && \
    rm -rf rclone.zip rclone-v1.70.1-linux-amd64 && \
    # Verify rclone version
    /usr/local/bin/rclone --version

WORKDIR /app

# Appuser und Verzeichnisse
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser && \
    mkdir -p /app/data /app/static /data && \
    chown -R appuser:appgroup /app /data

# Copy binary & static files
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rclone-gui /app/
COPY --from=builder /app/static /app/static
COPY .env /app/

# Berechtigungen & ausführbar machen
RUN chmod +x /app/rclone-gui

USER appuser

EXPOSE 8080

# Volumes für Config und Benutzer-Daten
VOLUME ["/app/data", "/data"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Umgebungsvariablen
ENV RCLONE_GUI_DEFAULT_PATH=/data
ENV RUST_LOG=info

# Startbefehl
CMD ["./rclone-gui", "--bind", "0.0.0.0:8080"]
