#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ is required"'
if ! command -v node >/dev/null 2>&1; then echo 'Install Node 24+ before starting TraceWeave.'; exit 1; fi
node -e 'if(Number(process.versions.node.split(".")[0])<24) {console.error("Node 24+ is required");process.exit(1)}'
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
fi
if ! .venv/bin/python -c 'import httpx,pydantic,pydantic_core' >/dev/null 2>&1; then
  .venv/bin/python -m pip install -r requirements.txt
fi
printf '\nTraceWeave: http://127.0.0.1:%s\nKeep this terminal open. Ctrl-C cancels app-owned analysis processes.\n' "${PORT:-18505}"
exec .venv/bin/python website/server.py --port "${PORT:-18505}"
