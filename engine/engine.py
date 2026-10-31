#!/usr/bin/env python3
"""Script entry point; optional project-local dependencies, no venv required."""
from pathlib import Path
import sys
local_deps = Path(__file__).resolve().parent / '.deps'
if local_deps.is_dir():
    sys.path.insert(0, str(local_deps))
from killchain.cli import main
if __name__ == '__main__':
    raise SystemExit(main())
