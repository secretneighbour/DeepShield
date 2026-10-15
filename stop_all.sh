#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== Stopping All DeepShield Laptop Services ==="

PID_FILE="$DIR/.services.pid"

if [ -f "$PID_FILE" ]; then
  echo "[*] Reading recorded PIDs from .services.pid..."
  while IFS= read -r pid; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo "    - Sending SIGTERM to process $pid..."
      kill "$pid" 2>/dev/null || true
    fi
  done < "$PID_FILE"
  
  # Allow graceful termination
  sleep 2
  
  # Force kill any lingering processes from file
  while IFS= read -r pid; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo "    - Force killing process $pid..."
      kill -9 "$pid" 2>/dev/null || true
    fi
  done < "$PID_FILE"
  
  rm -f "$PID_FILE"
  echo "[+] Removed .services.pid"
else
  echo "[i] No .services.pid found. Cleaning up by process signatures..."
fi

# Clean up any lingering uvicorn on port 8000
if command -v fuser &>/dev/null; then
  fuser -k 8000/tcp >/dev/null 2>&1 || true
  fuser -k 5173/tcp >/dev/null 2>&1 || true
else
  pkill -f "uvicorn app.main:app" >/dev/null 2>&1 || true
  pkill -f "vite --host" >/dev/null 2>&1 || true
fi

# Clean up ngrok tunnel process if running
pkill -f "ngrok http" >/dev/null 2>&1 || true

echo "[✓] All DeepShield laptop services and ngrok tunnels safely stopped."
