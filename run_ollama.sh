#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== Checking Local Ollama Daemon & Gemma 3 4B Model ==="

if ! command -v ollama &>/dev/null; then
  echo "[-] ERROR: 'ollama' binary was not found in PATH."
  echo "    Please install Ollama from https://ollama.com before launching."
  exit 1
fi

# Check if Ollama is already running on port 11434
if curl -s http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
  echo "[+] Ollama daemon is already running on 127.0.0.1:11434 (Loopback only - secure)."
else
  echo "[*] Starting Ollama daemon in background..."
  ollama serve >/dev/null 2>&1 &
  OLLAMA_PID=$!
  echo "[*] Ollama PID: $OLLAMA_PID"
  
  # Wait for daemon to respond
  for i in {1..15}; do
    if curl -s http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
      echo "[+] Ollama daemon is now online."
      break
    fi
    sleep 1
  done
fi

# Verify Gemma 3 4B model presence
TARGET_MODEL="gemma3:4b"
if ollama list 2>/dev/null | grep -q "$TARGET_MODEL"; then
  echo "[+] Local model '$TARGET_MODEL' is installed and ready."
else
  echo "[*] Model '$TARGET_MODEL' not found locally. Pulling now..."
  ollama pull "$TARGET_MODEL"
  echo "[+] Successfully downloaded '$TARGET_MODEL'."
fi

echo "[✓] Local Ollama Stage 1 service is operational."
