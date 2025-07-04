#!/bin/bash

# Rclone GUI Startup Script
# Usage: ./start.sh [OPTIONS]

# Check if rclone is installed
if ! command -v rclone &> /dev/null; then
    echo "❌ Error: rclone is not installed or not in PATH"
    echo "   Please install rclone first: https://rclone.org/install/"
    exit 1
fi

# Build if necessary
if [ ! -f "./target/release/rclone-gui" ]; then
    echo "🔨 Building application..."
    cargo build --release
fi

# Start the application with any passed arguments
./target/release/rclone-gui "$@"