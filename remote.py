#!/usr/bin/env python3
"""Install/connect through SSH, proxy the remote app locally and reconnect the tunnel."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import re
import signal
import shlex
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import webbrowser
import sys

ROOT = Path(__file__).resolve().parent
STATE = Path.home() / '.config/traceweave'
FILES = ('ai_hub.py','attack_catalog.json','MITRE_LICENSE.txt','remote.py','engine.py', 'bridge.ts', 'resources.py', 'worker.py', 'rules.json', 'requirements.txt', 'NOTICE.md', 'README.md')


def package(target):
    with tempfile.TemporaryDirectory(prefix='traceweave-bundle-') as temporary:
        stage = Path(temporary)
        for name in FILES: shutil.copy2(ROOT / name, stage / name)
        for name in ('vendor', 'website', 'deploy'):
            shutil.copytree(ROOT / name, stage / name, ignore=shutil.ignore_patterns('__pycache__','*.pyc','test_*.py','README.md'))
        manifest = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(stage.rglob('*')) if p.is_file()}
        (stage / 'bundle-manifest.json').write_text(json.dumps(manifest, sort_keys=True))
        with tarfile.open(target, 'w:gz') as archive:
            for child in stage.iterdir(): archive.add(child, arcname=child.name)
    return hashlib.sha256(Path(target).read_bytes()).hexdigest()


def validate(config):
    if not isinstance(config.get('host'),str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', config['host']): raise ValueError('Use a server DNS name or IPv4 address')
    if not isinstance(config.get('user'),str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,63}', config['user']): raise ValueError('Invalid SSH username')
    if type(config['port']) is not int or not 1 <= config['port'] <= 65535: raise ValueError('Invalid SSH port')
    key = Path(config['key']).expanduser().resolve()
    if not key.is_file(): raise ValueError('SSH key file not found')
    config['key'] = str(key)
    return config


def ssh(config, command=None, tty=False):
    args = ['ssh', '-i', config['key'], '-p', str(config['port']), '-l', config['user'],
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=ask', '-o', 'ConnectTimeout=10']
    if config.get('known_hosts'):
        args.extend(['-o','UserKnownHostsFile="'+str(config['known_hosts']).replace('\\','\\\\').replace('"','\\"')+'"','-o','StrictHostKeyChecking=yes'])
        args=[a.replace('StrictHostKeyChecking=ask','StrictHostKeyChecking=yes') for a in args]
    if config.get('batch'):args.extend(['-o','BatchMode=yes'])
    if tty: args.append('-t')
    args.append(config['host'])
    if command: args.append(command)
    return args


def setup(config):
    # Establish host trust interactively before any upload or privileged action.
    subprocess.run(ssh(config, 'true'), check=True)
    with tempfile.TemporaryDirectory(prefix='traceweave-setup-') as temporary:
        archive = Path(temporary) / 'agent.tar.gz'; checksum = package(archive)
        remote = '/tmp/traceweave-setup-' + os.urandom(8).hex()
        subprocess.run(ssh(config, 'umask 077; mkdir ' + shlex.quote(remote)), check=True)
        try:
            subprocess.run(['scp', *(['-o','UserKnownHostsFile="'+str(config['known_hosts']).replace('\\','\\\\').replace('"','\\"')+'"'] if config.get('known_hosts') else []), '-i', config['key'], '-P', str(config['port']), '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', str(archive), f"{config['user']}@{config['host']}:{remote}/agent.tar.gz"], check=True)
            verify = f"cd {shlex.quote(remote)} && echo '{checksum}  agent.tar.gz' | sha256sum -c - && tar -xzf agent.tar.gz && rm agent.tar.gz"
            subprocess.run(ssh(config, verify), check=True)
            print('One-time setup installs runtimes and unprivileged services. sudo may request your server password.')
            subprocess.run(ssh(config, f'sudo python3 {remote}/deploy/install.py {remote} {shlex.quote(config["user"])}', tty=True), check=True)
        finally:
            subprocess.run(ssh(config, 'rm -rf -- ' + shlex.quote(remote)), check=False)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = STATE / 'server.json'
    descriptor = os.open(profile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(profile,0o600)
    with os.fdopen(descriptor, 'w') as stream: json.dump(config, stream)


class Tunnel:
    def __init__(self, config, port):
        self.config, self.port = config, port
        self.stop = threading.Event(); self.process = None; self.connected = threading.Event()

    def run(self):
        delay = 1
        while not self.stop.is_set():
            args = [a.replace('StrictHostKeyChecking=ask','StrictHostKeyChecking=yes') for a in ssh(self.config)]
            args[-1:-1] = ['-N', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', '-L', f'127.0.0.1:{self.port}:127.0.0.1:18605']
            self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            started = time.monotonic()
            while self.process.poll() is None and not self.stop.wait(0.5):
                self.connected.set()
            self.connected.clear()
            if self.stop.is_set(): break
            delay = 1 if time.monotonic() - started > 30 else min(delay * 2, 30)
            self.stop.wait(delay)
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()

    def close(self): self.stop.set()


class Proxy(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self): self.forward()
    def do_POST(self): self.forward()
    def do_PUT(self): self.forward()
    def do_DELETE(self): self.forward()
    def forward(self):
        self.connection.settimeout(30)
        expected = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host') != expected or not self.path.startswith('/') or self.path.startswith('//'):
            self.send_error(403); return
        if self.command != 'GET' and self.headers.get('Origin') != 'http://' + expected:
            self.send_error(403); return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 80 * 1024**2 or self.headers.get('Transfer-Encoding'):
                self.send_error(413); return
        except ValueError:
            self.send_error(400); return
        connection = http.client.HTTPConnection('127.0.0.1', self.server.tunnel_port, timeout=140)
        started = False
        try:
            connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            for name in ('Content-Type', 'X-Demo-Token'):
                if self.headers.get(name): connection.putheader(name, self.headers[name])
            connection.putheader('Host', '127.0.0.1:18605')
            connection.putheader('Authorization', 'Bearer ' + self.server.agent_token)
            if self.command != 'GET': connection.putheader('Origin', 'http://127.0.0.1:18605')
            connection.putheader('Content-Length', str(size)); connection.endheaders()
            left = size
            while left:
                block = self.rfile.read(min(left, 65536))
                if not block: raise OSError('Incomplete request')
                connection.send(block); left -= len(block)
            response = connection.getresponse()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in ('connection', 'transfer-encoding', 'server', 'date'): self.send_header(name, value)
            self.end_headers(); started = True
            while block := response.read(65536): self.wfile.write(block)
        except (OSError, http.client.HTTPException):
            if not started:
                body = b'{"error":"SSH connection unavailable. Reconnecting; server jobs continue. Retry status before submitting again."}'
                self.send_response(503); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        finally: connection.close()


def connect(config, local_port, open_browser=True):
    # Token travels only over SSH into this backend process; never into browser state.
    result = subprocess.run(ssh(config, 'cat ~/.config/traceweave-agent/token'), check=True, capture_output=True, text=True,timeout=15)
    token = result.stdout.strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,100}', token): raise ValueError('Invalid agent token; run setup first')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0)); tunnel_port = probe.getsockname()[1]
    tunnel = Tunnel(config, tunnel_port)
    thread = threading.Thread(target=tunnel.run, daemon=True); thread.start()
    server = None
    try:
        server = ThreadingHTTPServer(('127.0.0.1', local_port), Proxy)
        server.agent_token = token; server.tunnel_port = tunnel_port
        url = f'http://127.0.0.1:{local_port}/'
        print('Remote TraceWeave:', url, '\nCtrl-C disconnects this client; remote jobs keep running.')
        tunnel.connected.wait(10)
        if open_browser: webbrowser.open(url)
        server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        if server: server.server_close()
        tunnel.close(); thread.join(timeout=10)


class WebConnection:
    """Own only the local client process; disconnect never stops remote analysis."""
    def __init__(self,data):
        self.folder=Path(data)/'remote';self.folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.pending={};self.config=None;self.process=None;self.lock=threading.RLock()

    def inspect(self,body):
        config=validate(dict(host=body.get('host'),user=body.get('user'),key=body.get('key'),port=body.get('port',22)))
        try:scan=subprocess.run(['ssh-keyscan','-T','5','-p',str(config['port']),config['host']],capture_output=True,text=True,timeout=10)
        except (subprocess.TimeoutExpired,OSError):raise ValueError('SSH inspection failed or timed out; check the host, port and OpenSSH installation') from None
        lines=[line for line in scan.stdout.splitlines() if line and not line.startswith('#')]
        if not lines or len(scan.stdout)>16000:raise ValueError('Could not obtain host keys; check host/SSH port')
        fingerprints={}
        for line in lines[:8]:
            result=subprocess.run(['ssh-keygen','-lf','-'],input=line+'\n',capture_output=True,text=True,timeout=3)
            if result.returncode==0:
                parts=result.stdout.split();fingerprints[parts[1]]=line
        if not fingerprints:raise ValueError('Server returned no valid host key')
        identifier=os.urandom(16).hex()
        with self.lock:
            self.pending={identifier:dict(config=config,keys=fingerprints,expires=time.monotonic()+300)}
        return dict(id=identifier,fingerprints=list(fingerprints),instruction='Compare with your server administrator before approving. A scanned key is not trusted automatically.')

    def approve(self,identifier,fingerprint):
        with self.lock:
            pending=self.pending.get(identifier)
            if not pending or pending['expires']<time.monotonic() or fingerprint not in pending['keys']:raise ValueError('Inspect the server and approve its fingerprint first')
            config=pending['config'];line=pending['keys'][fingerprint]
            name=hashlib.sha256((config['host']+':'+str(config['port'])).encode()).hexdigest()[:24]
            known=self.folder/(name+'.known_hosts')
            if known.exists() and known.read_text().strip()!=line.strip():raise ValueError('Pinned host key changed. Verify with the administrator before replacing the local pin file.')
            descriptor=os.open(known,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
            with os.fdopen(descriptor,'w') as stream:stream.write(line+'\n')
            self.config={**config,'known_hosts':str(known.resolve()),'batch':True}
            return dict(approved=True)

    def launch_setup(self):
        if not self.config:raise ValueError('Approve the server fingerprint first')
        c=self.config;script=self.folder/'setup.command'
        command=[sys.executable,str(ROOT/'remote.py'),'setup','--host',c['host'],'--user',c['user'],'--key',c['key'],'--port',str(c['port']),'--known-hosts',c['known_hosts'],'--local-port','18605','--no-browser']
        script.write_text('#!/bin/sh\nset -eu\n'+shlex.join(command)+'\n');os.chmod(script,0o700)
        if sys.platform=='darwin':subprocess.Popen(['open','-a','Terminal',str(script)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        else:
            terminal=shutil.which('x-terminal-emulator')
            if terminal:subprocess.Popen([terminal,'-e','sh',str(script)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            else:return dict(command='sh '+shlex.quote(str(script)),message='Run this setup command in your terminal for one-time sudo approval, then open the remote URL.')
        return dict(message='Setup opened in Terminal. Approve sudo there; no SSH password or private-key contents enter the website.',url='http://127.0.0.1:18605/')

    def start(self):
        with self.lock:
            if not self.config:raise ValueError('Approve the server fingerprint first')
            if self.process and self.process.poll() is None:return self.status()
            with socket.socket() as probe:
                try:probe.bind(('127.0.0.1',18605))
                except OSError:raise ValueError('Port 18605 is already in use; if setup is running in Terminal, open its remote URL') from None
            c=self.config
            args=[sys.executable,str(ROOT/'remote.py'),'connect','--host',c['host'],'--user',c['user'],'--key',c['key'],'--port',str(c['port']),'--known-hosts',c['known_hosts'],'--batch-mode','--local-port','18605','--no-browser']
            log=self.folder/'client.log'
            with log.open('wb') as stream:self.process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True,env={**os.environ,'PYTHONUNBUFFERED':'1'})
            return dict(state='connecting',url='http://127.0.0.1:18605/')

    def status(self):
        running=self.process is not None and self.process.poll() is None
        state='connecting' if running else 'disconnected'
        if running:
            try:
                import urllib.request
                with urllib.request.urlopen('http://127.0.0.1:18605/api/health',timeout=2) as response:
                    if response.status==200:state='connected'
            except (OSError,ValueError):pass
        return dict(state=state,url='http://127.0.0.1:18605/',host=self.config['host'] if self.config else None,message='Server jobs continue after local disconnection.' if running else 'Connect an installed agent, or use one-time Terminal setup. Load encrypted SSH keys with ssh-add first.')

    def close(self):
        with self.lock:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:self.process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid,signal.SIGKILL);self.process.wait()
            if self.process and isinstance(self.process.pid,int):
                try:os.killpg(self.process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
            self.process=None
            return dict(state='disconnected',remote_jobs_stopped=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'connect', 'package'))
    parser.add_argument('--host'); parser.add_argument('--user'); parser.add_argument('--key')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--local-port', type=int, default=18605)
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--known-hosts');parser.add_argument('--batch-mode',action='store_true')
    parser.add_argument('--output', default='traceweave-agent.tar.gz')
    args = parser.parse_args()
    if args.action == 'package':
        print('SHA256:', package(Path(args.output).resolve())); return
    profile = STATE / 'server.json'
    if args.action == 'connect' and not args.host:
        config = validate(json.loads(profile.read_text()))
    else:
        config = validate(dict(host=args.host or input('Server hostname/IP: ').strip(), user=args.user or input('SSH username: ').strip(), key=args.key or input('SSH key path: ').strip(), port=args.port))
    if args.known_hosts:config['known_hosts']=str(Path(args.known_hosts).expanduser().resolve())
    if args.batch_mode:config['batch']=True
    signal.signal(signal.SIGTERM,lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
    if args.action == 'setup': setup(config)
    connect(config, args.local_port, not args.no_browser)


if __name__ == '__main__': main()
