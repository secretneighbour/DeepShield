#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ -f "$DIR/.env" ]; then
  set -a
  source "$DIR/.env"
  set +a
fi

if ! command -v ngrok &>/dev/null; then
  echo "[-] ERROR: 'ngrok' binary was not found in PATH."
  echo "    Please install ngrok from https://ngrok.com/download before continuing."
  exit 1
fi

# Apply authtoken if provided in .env
if [ -n "$NGROK_AUTHTOKEN" ]; then
  echo "[*] Setting ngrok authtoken from .env..."
  ngrok config add-authtoken "$NGROK_AUTHTOKEN" >/dev/null 2>&1 || true
fi

PORT="${NGROK_PORT:-5173}"
echo "=== Starting ngrok Public HTTPS Tunnel ==="
echo "Forwarding to local reverse proxy on port: $PORT"

if [ -n "$NGROK_DOMAIN" ]; then
  echo "[+] Using persistent / reserved domain: $NGROK_DOMAIN"
  exec ngrok http --domain="$NGROK_DOMAIN" "$PORT"
else
  echo "[i] No persistent domain specified (NGROK_DOMAIN is empty in .env)."
  echo "    Generating temporary random ngrok HTTPS URL..."
  exec ngrok http "$PORT"
fi
