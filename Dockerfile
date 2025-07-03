# Multi-stage build for Rust application
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create src directory and dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached if dependencies don't change)
RUN cargo build --release
RUN rm -f target/release/deps/rclone_gui*

# Copy source code
COPY src/ ./src/
COPY static/ ./static/

# Build the application
RUN cargo build --release

# Final stage - minimal Alpine image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    rclone \
    && rm -rf /var/cache/apk/*

# Create app user for security
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p data/cfg static && \
    chown -R appuser:appgroup /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/rclone-gui /app/
COPY --from=builder /app/static/ /app/static/

# Copy .env file
COPY .env /app/

# Make binary executable
RUN chmod +x /app/rclone-gui

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Set environment variables
ENV RCLONE_GUI_DEFAULT_PATH=/data
ENV RUST_LOG=info

# Volume for persistent data
VOLUME ["/app/data"]

# Command to run the application
CMD ["./rclone-gui", "--bind", "0.0.0.0:8080"]