#!/usr/bin/env bash
# One-time backend setup: create the virtual environment and install numpy.
# Run this once, then activate the venv whenever you work on the backend.
#
#   cd backend
#   ./setup.sh
#   source .venv/bin/activate      # <- activate it (your prompt shows (.venv))
#   python api.py                  # now 'python' and 'pip' are the venv's
#
# To leave the venv later:  deactivate
set -e
cd "$(dirname "$0")"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "ERROR: Python 3 not found. Install it from https://www.python.org/downloads/"
  exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
  echo "==> Creating virtual environment (.venv)…"
  "$PY" -m venv .venv
fi

echo "==> Installing dependencies (numpy)…"
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

echo
echo "Done. Activate the environment with:"
echo "    source .venv/bin/activate"
echo "Then run the backend with:"
echo "    python api.py"
