#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "============================================================"
echo "   DeepShield — Autonomous Threat Intelligence Platform   "
echo "      See Beyond the Surface. Detect Deception.       "
echo "============================================================"

# Ensure .env exists
if [ ! -f "$DIR/.env" ]; then
  echo "[i] Creating .env from .env.example..."
  cp "$DIR/.env.example" "$DIR/.env"
fi

set -a
source "$DIR/.env"
set +a

# 1. Check Prerequisites
echo ""
echo "[*] Step 1: Checking system prerequisites..."

MISSING_DEPS=0
for cmd in node npm ollama ngrok; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "[-] Missing prerequisite command: $cmd"
    MISSING_DEPS=1
  fi
done

if [ ! -d "$DIR/venv" ]; then
  echo "[-] Virtual environment 'venv' not found at $DIR/venv"
  MISSING_DEPS=1
fi

if [ $MISSING_DEPS -ne 0 ]; then
  echo "[-] Please install missing prerequisites before starting."
  exit 1
fi
echo "[+] All required tools found (Node, npm, Ollama, ngrok, Python venv)."

# 2. Check / Start Ollama
echo ""
echo "[*] Step 2: Verifying Local Ollama Daemon & Gemma 3 4B..."
"$DIR/run_ollama.sh"

# 3. Clean up any previous stale PID file
PID_FILE="$DIR/.services.pid"
if [ -f "$PID_FILE" ]; then
  echo "[i] Cleaning up previous session PIDs..."
  "$DIR/stop_all.sh" >/dev/null 2>&1 || true
fi

# Track PIDs
BACKEND_PID=""
FRONTEND_PID=""
NGROK_PID=""

cleanup() {
  echo ""
  echo "=== Shutting down DeepShield laptop services... ==="
  if [ -n "$NGROK_PID" ] && kill -0 "$NGROK_PID" 2>/dev/null; then
    kill "$NGROK_PID" 2>/dev/null || true
  fi
  if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  echo "[✓] All services safely stopped."
  exit 0
}

# Trap SIGINT and SIGTERM when running in foreground
trap cleanup INT TERM

# 4. Start FastAPI Backend (Port 8000)
echo ""
echo "[*] Step 3: Launching FastAPI Security Core on 127.0.0.1:8000..."
setsid "$DIR/run_backend.sh" > "$DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "[+] Backend launched (PID: $BACKEND_PID, Log: backend.log)"

# Wait for backend health check
echo -n "[*] Waiting for backend readiness"
BACKEND_READY=0
for i in {1..20}; do
  if curl -s http://127.0.0.1:8000/api/health | grep -q "operational"; then
    BACKEND_READY=1
    break
  fi
  echo -n "."
  sleep 1
done
echo ""

if [ $BACKEND_READY -eq 0 ]; then
  echo "[-] ERROR: FastAPI backend failed to start. Inspect backend.log for details:"
  tail -n 20 "$DIR/backend.log"
  cleanup
fi
echo "[+] Backend is operational on http://127.0.0.1:8000"

# 5. Start Vite Frontend & Local Reverse Proxy (Port 5173)
echo ""
echo "[*] Step 4: Launching React/Vite Frontend & Reverse Proxy on port 5173..."
setsid "$DIR/run_frontend.sh" > "$DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "[+] Frontend launched (PID: $FRONTEND_PID, Log: frontend.log)"

# Wait for frontend readiness
echo -n "[*] Waiting for frontend readiness"
FRONTEND_READY=0
for i in {1..20}; do
  if curl -s http://127.0.0.1:5173/ | grep -q "<html\|<!DOCTYPE"; then
    FRONTEND_READY=1
    break
  fi
  echo -n "."
  sleep 1
done
echo ""

if [ $FRONTEND_READY -eq 0 ]; then
  echo "[-] ERROR: Vite frontend failed to start. Inspect frontend.log for details:"
  tail -n 20 "$DIR/frontend.log"
  cleanup
fi
echo "[+] Frontend & Reverse Proxy is operational on http://localhost:5173"

# 6. Start ngrok Tunnel
echo ""
echo "[*] Step 5: Launching ngrok Public HTTPS Tunnel..."
setsid "$DIR/run_ngrok.sh" > "$DIR/ngrok.log" 2>&1 &
NGROK_PID=$!
echo "[+] ngrok launched (PID: $NGROK_PID, Log: ngrok.log)"

# Save PIDs to file
echo "$BACKEND_PID" > "$PID_FILE"
echo "$FRONTEND_PID" >> "$PID_FILE"
echo "$NGROK_PID" >> "$PID_FILE"

# 7. Poll ngrok inspection API for the public URL
echo -n "[*] Discovering public ngrok HTTPS URL"
PUBLIC_URL=""
for i in {1..20}; do
  if curl -s http://127.0.0.1:4040/api/tunnels >/dev/null 2>&1; then
    PUBLIC_URL=$(curl -s http://127.0.0.1:4040/api/tunnels | grep -o 'https://[^"[:space:]]*\.ngrok[^"[:space:]]*' | head -n 1 || true)
    if [ -n "$PUBLIC_URL" ]; then
      break
    fi
  fi
  echo -n "."
  sleep 1
done
echo ""

# 8. Output Status Banner
echo ""
echo "======================================================================"
echo "          🚀 DEEPSHIELD IS RUNNING ON YOUR LAPTOP 🚀               "
echo "======================================================================"
if [ -n "$PUBLIC_URL" ]; then
  echo "  🌐 PUBLIC HTTPS URL:       $PUBLIC_URL"
else
  echo "  ⚠️  PUBLIC URL:             Initializing... (inspect via ./run_ngrok.sh)"
fi
echo "  💻 LOCAL REVERSE PROXY:    http://localhost:5173"
echo "  🔒 BACKEND SECURITY CORE:  http://127.0.0.1:8000"
echo "  📚 API DOCUMENTATION:      http://127.0.0.1:8000/docs"
echo "  🧠 LOCAL OLLAMA INFERENCE: http://127.0.0.1:11434 (Strictly Local)"
echo "  📊 NGROK LOCAL DASHBOARD:  http://127.0.0.1:4040"
echo "======================================================================"
echo ""
echo "[i] Processes running in background (PIDs saved in .services.pid):"
echo "    - Backend PID:  $BACKEND_PID"
echo "    - Frontend PID: $FRONTEND_PID"
echo "    - ngrok PID:    $NGROK_PID"
echo ""
echo "[i] To safely stop all services at any time, run: ./stop_all.sh"

# Check if --daemon was requested
if [ "$1" = "--daemon" ]; then
  disown "$BACKEND_PID" 2>/dev/null || true
  disown "$FRONTEND_PID" 2>/dev/null || true
  disown "$NGROK_PID" 2>/dev/null || true
  trap - INT TERM EXIT
  echo "[+] Started in daemon mode. Services will persist in background."
  exit 0
fi

echo "[i] Running in foreground. Press Ctrl+C to terminate all services..."
while true; do
  sleep 2
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "[-] Backend process died. Stopping remaining services..."
    cleanup
  fi
  if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    echo "[-] Frontend process died. Stopping remaining services..."
    cleanup
  fi
  if ! kill -0 "$NGROK_PID" 2>/dev/null; then
    echo "[-] ngrok process died. Stopping remaining services..."
    cleanup
  fi
done
