#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
pip install -r requirements.txt --break-system-packages -q
echo "Starting Cordon ZTA demo at http://localhost:8000/console/"
uvicorn zta_pep:app --host 0.0.0.0 --port 8000 --reload
