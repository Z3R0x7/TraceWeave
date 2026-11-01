#!/usr/bin/env python3
"""One-time privileged installer for Ubuntu 24.04+; invoked by remote.py."""
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import urllib.request


def run(*args): return subprocess.run(args, check=True)


def verify_bundle(bundle):
    bundle=Path(bundle).resolve()
    manifest=json.loads((bundle/'bundle-manifest.json').read_text())
    if not isinstance(manifest,dict) or not manifest:raise ValueError('Invalid bundle manifest')
    for relative,expected in manifest.items():
        if not isinstance(relative,str) or Path(relative).is_absolute() or not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):
            raise ValueError('Invalid bundle manifest entry')
        original=bundle/relative;item=original.resolve()
        if not item.is_relative_to(bundle) or original.is_symlink() or hashlib.sha256(item.read_bytes()).hexdigest()!=expected:
            raise ValueError('Bundle content integrity verification failed')
    return manifest


def install(bundle, user):
    if os.geteuid() != 0: raise SystemExit('Run installer with sudo')
    account = pwd.getpwnam(user)
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*', user): raise SystemExit('Invalid SSH account')
    os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os_release.get('ID', '').strip('"') != 'ubuntu' or float(os_release['VERSION_ID'].strip('"')) < 24.04:
        raise SystemExit('Automatic setup requires Ubuntu 24.04+ with systemd; other Linux hosts need manual runtime setup')
    for service in ('traceweave-api', 'traceweave-worker'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', service]).returncode == 0:
            raise SystemExit('Existing TraceWeave service is active. Do not update during analysis; stop it deliberately after completion.')
    bundle = Path(bundle).resolve()
    manifest = verify_bundle(bundle)
    run('apt-get', 'update')
    run('apt-get', 'install', '-y', 'python3', 'python3-venv', 'ca-certificates', 'xz-utils')
    root = Path('/opt/traceweave'); root.mkdir(parents=True, exist_ok=True)
    node = shutil.which('node')
    if node:
        version = subprocess.check_output([node, '--version'], text=True).strip()
        if int(version.lstrip('v').split('.')[0]) < 24: node = None
    if not node:
        architecture = {'x86_64': 'x64', 'aarch64': 'arm64'}.get(platform.machine())
        if not architecture: raise SystemExit('Supported server architectures: x86-64 and ARM64')
        base = 'https://nodejs.org/dist/latest-v24.x/'
        checksums = urllib.request.urlopen(base + 'SHASUMS256.txt', timeout=60).read().decode()
        digest, name = next(line.split() for line in checksums.splitlines() if line.endswith(f'-linux-{architecture}.tar.xz'))
        archive = root / 'node-download.tar.xz'
        with urllib.request.urlopen(base + name, timeout=60) as source, archive.open('wb') as target:
            shutil.copyfileobj(source, target)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest: raise SystemExit('Node archive checksum mismatch')
        with tarfile.open(archive) as source: source.extractall(root / 'runtimes', filter='data')
        node = str(root / 'runtimes' / name.removesuffix('.tar.xz') / 'bin/node')
        archive.unlink()
    bundle = Path(bundle).resolve()
    sys.path.insert(0, str(bundle))
    from resources import resource_budget
    budget = resource_budget()['memory_bytes']
    version = hashlib.sha256((bundle / 'bundle-manifest.json').read_bytes()).hexdigest()[:16]
    release = root / 'releases' / version
    release.parent.mkdir(exist_ok=True)
    if not release.exists():
        release.mkdir()
        for relative in (*manifest, 'bundle-manifest.json'):
            target=release/relative; target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(bundle/relative,target);os.chmod(target,0o644)

    run('python3', '-m', 'venv', str(release / '.venv'))
    python = str(release / '.venv/bin/python')
    run(python, '-m', 'pip', 'install', '-r', str(release / 'requirements.txt'))
    try: pwd.getpwnam('traceweave')
    except KeyError: run('useradd', '--system', '--home-dir', '/var/lib/traceweave', '--shell', '/usr/sbin/nologin', 'traceweave')
    service_account = pwd.getpwnam('traceweave')
    inputs=Path('/srv/traceweave-inputs');inputs.mkdir(mode=0o2750,exist_ok=True)
    os.chown(inputs,account.pw_uid,service_account.pw_gid);os.chmod(inputs,0o2750)
    data = Path('/var/lib/traceweave'); data.mkdir(mode=0o700, exist_ok=True)
    os.chown(data, service_account.pw_uid, service_account.pw_gid)
    config = Path('/etc/traceweave'); config.mkdir(mode=0o750, exist_ok=True)
    os.chown(config, 0, service_account.pw_gid)
    token = config / 'agent.token'
    if not token.exists(): token.write_text(secrets.token_urlsafe(48) + '\n')
    os.chmod(token, 0o640); os.chown(token, 0, service_account.pw_gid)
    ai_env=config/'ai.env'
    if not ai_env.exists():
        ai_env.write_text('AI_PROVIDER=groq\nAI_MODEL=openai/gpt-oss-120b\nGROQ_API_KEY=\nAI_MAX_PACKETS=10\n')
        os.chmod(ai_env,0o640);os.chown(ai_env,0,service_account.pw_gid)
    client = Path(account.pw_dir) / '.config/traceweave-agent'
    client.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(client, account.pw_uid, account.pw_gid)
    client_token = client / 'token'; shutil.copyfile(token, client_token)
    os.chmod(client_token, 0o600); os.chown(client_token, account.pw_uid, account.pw_gid)
    units = Path('/etc/systemd/system')
    (units / 'traceweave.slice').write_text(f'[Unit]\nDescription=TraceWeave combined resource budget\n[Slice]\nMemoryAccounting=yes\nMemoryHigh={int(budget*.9)}\nMemoryMax={budget}\nMemorySwapMax=0\n')
    common = f'''User=traceweave
Group=traceweave
WorkingDirectory={release}
Environment=PATH={Path(node).parent}:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=TRACEWEAVE_DATA={data}
Environment=TRACEWEAVE_WORKER_SOCKET=/run/traceweave/worker.sock
Environment=TRACEWEAVE_AGENT_TOKEN_FILE={token}
Environment=TRACEWEAVE_ENV_FILE=/etc/traceweave/ai.env
RuntimeDirectory=traceweave
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
UMask=0077
Slice=traceweave.slice
Restart=on-failure
RestartSec=3
KillMode=control-group
TimeoutStopSec=20
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={data} /run/traceweave
'''
    for name, command, dependencies in (
        ('worker', f'{python} {release}/worker.py', ''),
        ('api', f'{python} {release}/website/server.py --port 18605', 'Wants=traceweave-worker.service\nAfter=traceweave-worker.service\n')):
        (units / f'traceweave-{name}.service').write_text(f'[Unit]\nDescription=TraceWeave {name}\nAfter=network-online.target\n{dependencies}[Service]\n{common}ExecStart={command}\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'traceweave-worker.service', 'traceweave-api.service')
    print('Installed release', version, '; combined memory ceiling', budget, 'bytes. API bound to loopback port 18605.')


if __name__ == '__main__': install(sys.argv[1], sys.argv[2])
