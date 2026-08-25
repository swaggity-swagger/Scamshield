#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/backend"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install -q -r requirements.txt
echo "Open http://127.0.0.1:8000 in your browser"
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
