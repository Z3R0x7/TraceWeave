from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import datetime, timezone

CONTRACT = '1.0'
SECRET_KEYS = re.compile(r'password|passwd|secret|token|authorization|api[_-]?key|credential', re.I)
SECRET_TEXT = re.compile(r'(?i)(bearer\s+|(?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*)([^\s,;]+)')

def utcnow():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def iso(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    return value

def digest(value, n=24):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:n]

def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, default=iso, allow_nan=False)
            f.write('\n')
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def load_json(path):
    with Path(path).open(encoding='utf-8') as f:
        return json.load(f)

def sanitize(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if SECRET_KEYS.search(k) else sanitize(v) for k, v in value.items()}
    if isinstance(value, list): return [sanitize(x) for x in value]
    if isinstance(value, str): return SECRET_TEXT.sub(r'\1[REDACTED]', value)
    return value

def within(root, relative):
    root = Path(root).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root): raise ValueError('Artifact path escapes run directory')
    return target

def sql_string(value):
    return "'" + str(value).replace("'", "''") + "'"
