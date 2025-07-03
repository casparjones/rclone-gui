#!/bin/bash

# Rclone GUI Startup Script
# Usage: ./start.sh [OPTIONS]

echo "🚀 Starting Rclone GUI..."
echo "📁 Working directory: $(pwd)"

# Show current default path configuration
if [ -f ".env" ]; then
    DEFAULT_PATH=$(grep "RCLONE_GUI_DEFAULT_PATH" .env | cut -d'=' -f2)
    if [ ! -z "$DEFAULT_PATH" ]; then
        echo "🏠 Default browser path: $DEFAULT_PATH"
    fi
fi

# Check if rclone is installed
if ! command -v rclone &> /dev/null; then
    echo "❌ Error: rclone is not installed or not in PATH"
    echo "   Please install rclone first: https://rclone.org/install/"
    exit 1
fi

echo "✅ rclone found: $(which rclone)"

# Build if necessary
if [ ! -f "./target/release/rclone-gui" ]; then
    echo "🔨 Building application..."
    cargo build --release
fi

echo "🌐 Starting web server..."
echo "   Open your browser to: http://127.0.0.1:8080"
echo "   Press Ctrl+C to stop"
echo ""

# Start the application with any passed arguments
./target/release/rclone-gui "$@"