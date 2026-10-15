#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/frontend"

echo "=== Starting DeepShield Vite Frontend & Local Reverse Proxy ==="
echo "Local frontend & proxy running at: http://localhost:5173"
echo "Reverse proxying /api/* requests to FastAPI backend on port 8000"
exec npx vite --host 0.0.0.0 --port 5173
