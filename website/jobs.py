"""Durable local jobs. Secrets and subprocess handles are never persisted."""
import json,os,secrets,shutil,signal,subprocess,sys,threading,time,hashlib
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
RUNS=Path(os.environ.get('TRACEWEAVE_DATA', str(ROOT/'runs')))/'website'
LOCK=threading.RLock();PROCESSES={};STARTING=set();RUNTIME_CONFIG=None;CANCEL_AI=None
ACTIVE={'uploading','queued','running','cancelling','detached','indexing'}
def now():return datetime.now(timezone.utc).isoformat()
def save(job):
 path=RUNS/job['id']/'job.json';temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(job,indent=2)+'\n');os.replace(temporary,path)
def get(identifier):
 if not isinstance(identifier,str) or not identifier.startswith('web_') or not all(c.isalnum() or c=='_' for c in identifier):raise ValueError('Invalid job ID')
 try:
  job=json.loads((RUNS/identifier/'job.json').read_text())
  if job['status']=='uploading':
   recovered=False
   for entry in job['files']:
    path=Path(entry['path'])
    if not entry['local'] and not entry['received'] and path.is_file() and path.stat().st_size==entry['size']:
     entry.update(received=True,received_bytes=entry['size']);recovered=True
   if recovered:save(job)
  return job
 except OSError:raise ValueError('Job not found') from None
def remote_worker():
 return bool(os.environ.get('TRACEWEAVE_WORKER_SOCKET')) and not os.environ.get('TRACEWEAVE_WORKER_PROCESS')
def worker_request(command,**body):
 sys.path.insert(0,str(ROOT))
 from worker import request
 return request(command,**body)
def history():
 if remote_worker():return worker_request('history')
 RUNS.mkdir(parents=True,exist_ok=True)
 with LOCK:
  result=[]
  for path in sorted(RUNS.glob('web_*/job.json'),reverse=True):
   try:job=get(path.parent.name)
   except (OSError,ValueError):continue
   if job['status'] in {'running','queued','cancelling','detached','indexing'} and job['id'] not in PROCESSES and job['id'] not in STARTING:
    summary=Path(job['output'])/'summary.json'
    if summary.exists():job['status']='completed';job['error']='Recovered completed engine output; select Open results to index it.'
    elif job.get('pid'):
     try:os.kill(job['pid'],0);job['status']='detached';job['error']='Server tracking was interrupted and the recorded process may still be alive. New analysis is blocked until it exits; do not start a duplicate.'
     except ProcessLookupError:job['status']='interrupted';job['error']='Analysis was interrupted. Original inputs and partial results are retained.'
     except PermissionError:job['status']='detached'
    else:job['status']='interrupted';job['error']='Queued analysis was interrupted; start a new run.'
    save(job)
   result.append(status(job))
  result.sort(key=lambda job:job.get('created_at',''),reverse=True)
  return result[:30]
def status(job):
 result={k:v for k,v in job.items() if k not in {'files','pid'}}
 result['files']=[{k:v for k,v in e.items() if k!='path'} for e in job['files']]
 result['uploaded']=sum(e['received'] for e in job['files']);result['total_bytes']=sum(e['size'] for e in job['files'])
 try:result['progress']=json.loads((Path(job['output'])/'progress.json').read_text())
 except (OSError,ValueError):pass
 return result
def latest():
 entries=history();return entries[0] if entries else {'status':'idle'}
def register_source(value):
 if not isinstance(value,str) or not value or len(value)>4096:raise ValueError('Invalid source path')
 path=Path(value).expanduser().resolve()
 if not path.is_file() or path.suffix.lower() not in {'.log','.txt','.csv','.json','.jsonl','.ndjson','.gz'}:raise ValueError('Choose a readable supported log file')
 with path.open('rb') as stream:stream.read(1)
 stat=path.stat();identifier=secrets.token_hex(16)
 folder=RUNS.parent/'sources';folder.mkdir(parents=True,exist_ok=True,mode=0o700)
 record=dict(id=identifier,path=str(path),size=stat.st_size,mtime_ns=stat.st_mtime_ns,inode=stat.st_ino,name=path.name)
 target=folder/(identifier+'.json')
 descriptor=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(descriptor,'w') as stream:json.dump(record,stream)
 return {k:record[k] for k in ('id','name','size')}
def registered_sources(identifiers):
 if not isinstance(identifiers,list) or not 1<=len(identifiers)<=16:raise ValueError('Choose 1–16 registered sources')
 paths=[]
 for identifier in identifiers:
  if not isinstance(identifier,str) or len(identifier)!=32 or any(c not in '0123456789abcdef' for c in identifier):raise ValueError('Invalid source ID')
  try:record=json.loads((RUNS.parent/'sources'/(identifier+'.json')).read_text());stat=Path(record['path']).stat()
  except (OSError,ValueError):raise ValueError('Source is unavailable') from None
  if (stat.st_size,stat.st_mtime_ns,stat.st_ino)!=(record['size'],record['mtime_ns'],record['inode']):raise ValueError('Registered source changed; register it again')
  paths.append(record['path'])
 return paths
def create(files=None,paths=None,request_id=None):
 with LOCK:
  request_index=None
  if request_id is not None:
   if not isinstance(request_id,str) or len(request_id)!=36 or any(c not in '0123456789abcdef-' for c in request_id):raise ValueError('Invalid request ID')
   folder=RUNS.parent/'requests';folder.mkdir(parents=True,exist_ok=True)
   request_index=folder/request_id
   if request_index.exists():return status(get(request_index.read_text()))
  if any(j['status'] in ACTIVE for j in history()):raise ValueError('Finish or cancel the active job first.')
  entries=[]
  if paths:
   if not isinstance(paths,list) or not all(isinstance(p,str) for p in paths):raise ValueError('Invalid local paths')
   for p in paths:
    path=Path(p).expanduser().resolve()
    if not path.is_file():raise ValueError('Each local input must be an existing file.')
    stat=path.stat()
    entries.append(dict(name=path.name,path=str(path),size=stat.st_size,mtime_ns=stat.st_mtime_ns,inode=stat.st_ino,received=True,received_bytes=stat.st_size,local=True))
  else:
   if not isinstance(files,list):raise ValueError('Choose log files or local paths.')
   for entry in files:
    if not isinstance(entry,dict) or not isinstance(entry.get('name'),str) or type(entry.get('size')) is not int or entry['size']<=0:raise ValueError('Invalid file manifest')
    name=Path(entry['name']).name[:180]
    if not name or name in ('.','..') or '\x00' in name:raise ValueError('Invalid filename')
    entries.append(dict(name=name,size=entry['size'],received=False,received_bytes=0,local=False,modified_ms=entry.get('modified_ms')))
  if not 1<=len(entries)<=16:raise ValueError('Choose 1–16 log files.')
  if any(Path(e['name']).suffix.lower() not in {'.log','.txt','.csv','.json','.jsonl','.ndjson','.gz'} for e in entries):raise ValueError('Supported: log, txt, CSV, JSONL/NDJSON, JSON and gzip.')
  total=sum(e['size'] for e in entries);RUNS.mkdir(parents=True,exist_ok=True)
  if shutil.disk_usage(RUNS).free<total*6+3*1024**3:raise ValueError('Insufficient disk headroom: allow at least 6× source bytes plus 3 GiB; actual expansion is monitored by the engine/OS.')
  identifier='web_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+secrets.token_hex(4)
  root=RUNS/identifier;(root/'inputs').mkdir(parents=True)
  for index,entry in enumerate(entries):
   if not entry['local']:entry['path']=str(root/'inputs'/f'{index:02d}_{entry["name"]}')
  job=dict(id=identifier,status='uploading',created_at=now(),files=entries,output=str(root/'output'),log=str(root/'engine.log'))
  save(job)
  if request_index is not None:request_index.write_text(identifier)
  return status(job)
def receive(identifier,index,offset,stream,length):
 with LOCK:
  job=get(identifier)
  if job['status']!='uploading' or not 0<=index<len(job['files']):raise ValueError('Upload is not active')
  entry=job['files'][index]
  if entry['local'] or entry['received'] or not 0<length<=4*1024**2 or offset!=entry['received_bytes'] or offset+length>entry['size']:raise ValueError('Unexpected upload offset or chunk size')
  target=Path(entry['path']);part=target.with_suffix(target.suffix+'.part')
  with part.open('ab') as handle:
   handle.truncate(offset);remaining=length
   while remaining:
    block=stream.read(min(remaining,65536))
    if not block:raise ValueError('Upload interrupted; retry from the saved offset.')
    handle.write(block);remaining-=len(block)
  entry['received_bytes']+=length
  if entry['received_bytes']==entry['size']:part.replace(target);entry['received']=True
  save(job);return status(job)
def start(identifier,activate,configuration):
 if remote_worker():return worker_request('start',id=identifier)
 with LOCK:
  job=get(identifier)
  if job['status'] in {'queued','running','indexing','completed'}:return status(job)
  if job['status']!='uploading' or not all(e['received'] for e in job['files']):raise ValueError('Complete all uploads first.')
  for entry in job['files']:
   if entry['local']:
    stat=Path(entry['path']).stat()
    if (stat.st_size,stat.st_mtime_ns,stat.st_ino)!=(entry['size'],entry['mtime_ns'],entry['inode']):raise ValueError('Input changed before analysis; create a new job')
  config=configuration() # Validate credentials locally before starting expensive work.
  job['status']='queued';save(job);STARTING.add(identifier)
 def work():
  overall_started=time.monotonic()
  try:
   with LOCK:
    current=get(identifier)
    if current['status']!='queued':return
    env=os.environ.copy();command=[sys.executable,str(ROOT/'engine.py')]
    for entry in current['files']:command.extend(['--input',entry['path']])
    command.extend(['--output',current['output'],'--env',os.devnull])
    env.update(AI_PROVIDER=config['provider'],AI_MODEL=config['model'],AI_MAX_PACKETS=str(config['packets']),AI_TIMEOUT_SECONDS=str(config['timeout']))
    if config.get('hub'):
     for name in list(env):
      if name.endswith('_API_KEY') or name=='AI_CREDENTIALS_JSON':env.pop(name,None)
     env.update(TRACEWEAVE_AI_USE_HUB='1',TRACEWEAVE_AI_JOB_ID=identifier)
    else:env[config['provider'].upper()+'_API_KEY']=config['key']
    with Path(current['log']).open('xb') as log:
     process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True)
    PROCESSES[identifier]=process;current.update(status='running',pid=process.pid,started_at=now());save(current)
   code=process.wait()
   with LOCK:
    current=get(identifier)
    if current['status']=='cancelling':current['status']='cancelled'
    elif code:current.update(status='failed',error='Engine exited with code '+str(code)+'. Inspect the retained engine log.')
    else:current.update(status='indexing',engine_completed=True,viewer_status='indexing')
    current['finished_at']=now();save(current)
   if current['status']=='indexing':
    try:
     index_started=time.monotonic();activate(current['output'])
     elapsed=time.monotonic()-overall_started
     with LOCK:
      current=get(identifier);current['performance']=dict(elapsed_seconds=elapsed,index_seconds=time.monotonic()-index_started,within_three_hours=elapsed<10800,scope='engine with configured AI and investigation indexing; upload excluded',tier_30gb_size_met=sum(e['size'] for e in current['files'])>=30_000_000_000)
     with LOCK:
      current.update(status='completed',viewer_status='ready');save(current)
    except Exception:
     with LOCK:current=get(identifier);current.update(status='completed',viewer_status='failed',error='Engine completed; viewer indexing failed. Results are retained and can be reopened.');save(current)
  except Exception:
   with LOCK:current=get(identifier);current.update(status='failed',error='Job could not start. Check backend credentials/runtime and retained artifacts.');save(current)
  finally:
   with LOCK:PROCESSES.pop(identifier,None);STARTING.discard(identifier)
 threading.Thread(target=work,daemon=True).start();return status(job)
def cancel(identifier):
 if remote_worker():return worker_request('cancel',id=identifier)
 with LOCK:
  job=get(identifier)
  if job['status']=='uploading' or job['status']=='queued':job['status']='cancelled';save(job);return status(job)
  process=PROCESSES.get(identifier)
  if process is None or job['status'] not in {'running','cancelling'}:raise ValueError('No tracked process to cancel. Detached jobs require operator recovery.')
  job['status']='cancelling';save(job)
  if CANCEL_AI:CANCEL_AI(identifier)
  try:os.killpg(process.pid,signal.SIGTERM)
  except ProcessLookupError:pass
 def finish():
  try:process.wait(timeout=5)
  except subprocess.TimeoutExpired:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
 threading.Thread(target=finish,daemon=True).start();return status(job)
def stop_owned():
 for identifier in list(PROCESSES):
  try:cancel(identifier)
  except ValueError:pass
