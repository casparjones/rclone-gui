# -------- Build Stage --------
FROM rust:1.87-slim-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy only dependency files for better caching
COPY Cargo.toml Cargo.lock ./

# Dummy main to build dependencies layer
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Pre-build dependencies
RUN cargo build --release && rm -rf target/release/deps/rclone_gui*

# Now copy the real source
COPY src/ ./src/
COPY static/ ./static/

# Build actual application
RUN cargo build --release

# -------- Runtime Stage --------
FROM alpine:3.19

# Upgrade base packages (minimiert CVEs)
RUN apk update && apk upgrade && \
    apk add --no-cache \
        ca-certificates \
        rclone \
        wget && \
    rm -rf /var/cache/apk/*

# Create app user
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app

# Erstelle Datenverzeichnisse
RUN mkdir -p data/cfg static && \
    chown -R appuser:appgroup /app

# Copy build result
COPY --from=builder /app/target/release/rclone-gui /app/
COPY --from=builder /app/static/ /app/static/

# Optional: .env Datei (falls vorhanden)
COPY .env /app/

# Berechtigungen & Sicherheit
RUN chmod +x /app/rclone-gui

# Nutze non-root user
USER appuser

# Expose port & volume
EXPOSE 8080
VOLUME ["/app/data"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Environment
ENV RCLONE_GUI_DEFAULT_PATH=/data
ENV RUST_LOG=info

# Start command
CMD ["./rclone-gui", "--bind", "0.0.0.0:8080"]
