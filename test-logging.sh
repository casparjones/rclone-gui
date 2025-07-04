#!/bin/bash

echo "🧪 Testing server logging..."
echo ""

echo "📨 Testing GET request to home page:"
curl -s http://127.0.0.1:8080/ > /dev/null

echo ""
echo "📨 Testing GET request to sync jobs:"
curl -s http://127.0.0.1:8080/api/sync > /dev/null

echo ""
echo "📨 Testing GET request to configs:"
curl -s http://127.0.0.1:8080/api/configs > /dev/null

echo ""
echo "📨 Testing 404 request:"
curl -s http://127.0.0.1:8080/api/nonexistent > /dev/null

echo ""
echo "✅ Test requests completed - check server console for logs!"