#!/usr/bin/env bash
# Start the whole prototype with one command:
#   - creates a Python virtual environment (backend/.venv) on first run,
#   - installs the backend's one dependency (numpy) into it,
#   - starts the Python API (live stream + JSON API),
#   - installs the frontend packages on first run,
#   - starts the Vite React dev server.
# Ctrl+C stops both.
#
#   ./dev.sh
#
# Then open the URL Vite prints (usually http://localhost:5173).

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"

# ---- pick a Python (prefer python3) ----
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "ERROR: Python 3 was not found. Install it from https://www.python.org/downloads/ and try again."
  exit 1
fi

# ---- backend virtualenv ----
cd "$HERE/backend"
VENV="$HERE/backend/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo "==> Creating Python virtual environment (backend/.venv)…"
  "$PY" -m venv "$VENV"
fi
VPY="$VENV/bin/python"
echo "==> Installing backend dependencies (numpy) into the venv…"
"$VPY" -m pip install --quiet --upgrade pip
"$VPY" -m pip install --quiet -r requirements.txt

echo "==> Starting backend API on http://127.0.0.1:8000"
"$VPY" api.py --port 8000 --speed 0.7 &
BACK=$!

cleanup() { echo; echo "==> Stopping…"; kill "$BACK" 2>/dev/null || true; exit 0; }
trap cleanup INT TERM

# ---- frontend ----
cd "$HERE/frontend"
if [ ! -d node_modules ]; then
  echo "==> Installing frontend packages (first run only)…"
  npm install
fi
echo "==> Starting Vite dev server…"
npm run dev

cleanup
