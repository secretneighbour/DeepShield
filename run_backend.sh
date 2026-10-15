#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== Starting DeepShield FastAPI Security Core ==="
if [ -f "$DIR/.env" ]; then
  set -a
  source "$DIR/.env"
  set +a
fi

if [ -d "$DIR/venv" ]; then
  PYTHON="$DIR/venv/bin/python3"
else
  PYTHON="python3"
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

export PYTHONPATH="$DIR/backend:$PYTHONPATH"
echo "Listening locally on: http://$HOST:$PORT"
exec "$PYTHON" -m uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
