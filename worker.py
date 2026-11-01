#!/usr/bin/env python3
"""Independent worker and shared AI hub on a private, bounded Unix RPC socket."""
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import sys
import threading
import subprocess
import tempfile
import hashlib
import time

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'website'))
from website import jobs
from ai_hub import Hub, AIError


def request(command,**body):
    path=os.environ.get('TRACEWEAVE_WORKER_SOCKET')
    if not path:raise ValueError('Remote worker is not configured')
    payload=json.dumps(dict(command=command,**body),ensure_ascii=False).encode()+b'\n'
    if len(payload)>256*1024:raise ValueError('Worker request exceeds 256 KiB')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(75 if command=='ai_call' else 15);connection.connect(path);connection.sendall(payload)
        with connection.makefile('rb') as stream:data=stream.readline(128*1024+1)
        if len(data)>128*1024:raise ValueError('Worker response exceeded limit')
        result=json.loads(data)
        if 'error' in result:raise AIError(result.get('code','worker_error'),result['error'],result.get('retry_at'))
        return result['result']


def start_local():
    if os.environ.get('TRACEWEAVE_WORKER_SOCKET'):return None
    data=Path(os.environ.get('TRACEWEAVE_DATA',str(ROOT/'runs'))).resolve();data.mkdir(parents=True,exist_ok=True)
    name=hashlib.sha256(str(data).encode()).hexdigest()[:16]
    folder=Path(tempfile.gettempdir())/('traceweave-'+str(os.getuid())+'-'+name)
    if folder.is_symlink():raise ValueError('Unsafe local worker directory')
    folder.mkdir(mode=0o700,exist_ok=True)
    if folder.stat().st_uid!=os.getuid():raise ValueError('Local worker directory belongs to another user')
    os.chmod(folder,0o700)
    os.environ.update(TRACEWEAVE_WORKER_SOCKET=str(folder/'worker.sock'),TRACEWEAVE_DATA=str(data),TRACEWEAVE_LOCAL_APP='1')
    if Path(os.environ['TRACEWEAVE_WORKER_SOCKET']).exists():
        try:request('health');return None
        except (ConnectionRefusedError,FileNotFoundError):pass
    env=os.environ.copy();env.pop('TRACEWEAVE_AI_USE_HUB',None)
    with (data/'worker.log').open('ab') as log:process=subprocess.Popen([sys.executable,str(ROOT/'worker.py')],env=env,stdout=log,stderr=log)
    until=time.monotonic()+8
    while time.monotonic()<until:
        if process.poll() is not None:raise RuntimeError('Local worker failed; inspect runs/worker.log')
        if Path(os.environ['TRACEWEAVE_WORKER_SOCKET']).exists():
            request('health');return process
        time.sleep(.05)
    process.terminate();process.wait(timeout=10);raise RuntimeError('Local worker did not become ready')


def serve():
    os.environ['TRACEWEAVE_WORKER_PROCESS']='1'
    from website import server
    path=Path(os.environ['TRACEWEAVE_WORKER_SOCKET']);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.exists():
        try:request('health')
        except (OSError,ValueError):path.unlink()
        else:raise SystemExit('Worker already running')
    hub=Hub()
    def load_env():
        config=server.engine_module().load_configuration(Path(os.environ.get('TRACEWEAVE_ENV_FILE',str(ROOT/'.env'))))
        return hub.configure(config)
    try:load_env()
    except (OSError,ValueError):pass
    jobs.CANCEL_AI=hub.cancel_owner
    def dispatch(body):
        command=body['command']
        if command=='health':return dict(ready=True,ai_configured=hub.status()['configured'])
        if command=='configuration':return hub.configuration()
        if command=='connect':return hub.configure(body['config'])
        if command=='ai_reload':return load_env()
        if command=='ai_add':return hub.add(body['credential'],primary=body.get('primary',False))
        if command=='ai_remove':return hub.remove(body['id'])
        if command=='ai_status':return hub.status()
        if command=='ai_budget':return hub.set_packets(body['packets'])
        if command=='ai_session_status':return hub.session_status(body['session'])
        if command=='ai_open':return hub.open(**{k:v for k,v in body.items() if k!='command'})
        if command=='ai_call':return hub.call(**{k:v for k,v in body.items() if k!='command'})
        if command=='ai_commit':return hub.commit(body['session'],body.get('accepted',True))
        if command=='ai_close':return hub.close_session(body['identifier'])
        if command=='recover':threading.Thread(target=server.recover_latest_outputs,daemon=True).start();return dict(queued=True)
        if command=='history':return jobs.history()
        if command=='start':return jobs.start(body['id'],server.activate,hub.configuration)
        if command=='cancel':return jobs.cancel(body['id'])
        raise ValueError('Unknown worker command')
    class RPC(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(75)
            try:
                line=self.rfile.readline(256*1024+1)
                if len(line)>256*1024:raise ValueError('Worker request exceeded limit')
                reply=dict(result=dispatch(json.loads(line)))
            except Exception as exc:
                reply=dict(error=str(exc) if isinstance(exc,ValueError) else 'Worker operation failed',code=getattr(exc,'code','worker_error'),retry_at=getattr(exc,'retry_at',None))
            try:self.wfile.write(json.dumps(reply,ensure_ascii=False).encode()+b'\n')
            except OSError:pass
    class RPCServer(socketserver.ThreadingUnixStreamServer):
        daemon_threads=True
        def __init__(self,*args):self.slots=threading.BoundedSemaphore(12);super().__init__(*args)
        def process_request(self,connection,address):
            if not self.slots.acquire(blocking=False):connection.close();return
            try:super().process_request(connection,address)
            except BaseException:self.slots.release();raise
        def process_request_thread(self,*args):
            try:super().process_request_thread(*args)
            finally:self.slots.release()
    signal.signal(signal.SIGTERM,lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        with RPCServer(str(path),RPC) as rpc:
            os.chmod(path,0o600)
            threading.Thread(target=server.recover_latest_outputs,daemon=True).start()
            try:rpc.serve_forever(poll_interval=.2)
            except KeyboardInterrupt:pass
    finally:
        jobs.stop_owned()
        for process in list(jobs.PROCESSES.values()):
            try:process.wait(timeout=10)
            except Exception:pass
        hub.close();path.unlink(missing_ok=True)


if __name__=='__main__':serve()
