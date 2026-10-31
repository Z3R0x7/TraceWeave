from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import threading
import time
import psutil
import resource
import sys
import duckdb
from .common import atomic_json, utcnow, CONTRACT
from .ingest import inputs
from .parallel import ingest_parallel,RunCancelled,control
from .audit import audit_file
from .analysis import prepare,detect,export_results,RULES

class Progress(dict):
    def __init__(self,run,job_id,total,callback=None):
        super().__init__(contract_version=CONTRACT,job_id=job_id,status='running',phase='starting',
          processed_bytes=0,total_bytes=total,records_read=0,records_parsed=0,malformed_records=0,
          missing_critical_fields=0,unknown_event_types=0,duplicate_records=0,out_of_order_records=0,
          detections_found=0,incidents_found=0,updated_at=utcnow(),error=None)
        self.run=run;self.callback=callback;self.last=0;self.guard=None
    def publish(self,force=False):
        now=time.monotonic()
        if not force and now-self.last<.5:return
        if self.guard and self['status']=='running':self.guard()
        self['updated_at']=utcnow();atomic_json(self.run/'progress.v1.json',self)
        if self.callback:self.callback(dict(self))
        self.last=now

class Monitor:
    def __init__(self,run,min_free_gb,memory_gb=None,deadline=None):
        self.run=run;self.min_free=min_free_gb*2**30;self.peak=0;self.peak_temp=0;self.error=None;self.rss_available=False
        self.memory_limit=memory_gb*2**30 if memory_gb else None;self.deadline=deadline;self.con=None
        self.stop=threading.Event();self.thread=threading.Thread(target=self.sample,daemon=True)
    def sample(self):
        process=psutil.Process()
        while not self.stop.is_set():
            try:
                rss=process.memory_info().rss;self.rss_available=True
                for p in process.children(recursive=True):
                    try:rss+=p.memory_info().rss
                    except psutil.Error:pass
                self.peak=max(self.peak,rss)
                temp=self.run/'tmp'
                if temp.exists():
                    self.peak_temp=max(self.peak_temp,sum(p.stat().st_size for p in temp.glob('*') if p.is_file()))
                if shutil.disk_usage(self.run).free<self.min_free:self.error='Workspace free space fell below configured reserve'
                if self.memory_limit and rss>self.memory_limit:self.error='Sampled process-tree memory exceeded the configured total budget'
                if self.deadline and time.time()>self.deadline:self.error='Configured run timeout reached'
                if (self.run/'CANCEL').exists():self.error='Run cancelled by user'
                if self.error:
                    (self.run/'ABORT').touch()
                    if self.con:self.con.interrupt()
            except (OSError,psutil.Error):pass
            self.stop.wait(.25)
    def finish(self):
        self.stop.set();self.thread.join(timeout=2)

def analyze(input_path,output_path,job_id,config,callback=None,resume=False):
    source=Path(input_path).resolve();run=Path(output_path).resolve()
    if source.is_dir() and (run==source or run.is_relative_to(source)):
        raise ValueError('Output directory must be outside the input directory')
    files=inputs(source); total=sum(p.stat().st_size for p in files)
    if config['hardware']['disk_free_gb']<config['min_free_gb']:
        raise ValueError('Insufficient disk reserve before start')
    if (run/'.analysis.lock').exists():
        try:owner=int((run/'.analysis.lock').read_text())
        except ValueError:raise ValueError('Invalid analysis lock; verify no process is active')
        if psutil.pid_exists(owner):raise ValueError('Another process owns this run')
    if resume:
        if not run.is_dir():raise ValueError('Resume requires an existing failed/cancelled run')
        if (run/'manifest.v1.json').exists() and json.loads((run/'manifest.v1.json').read_text()).get('status')=='completed':raise ValueError('Completed run cannot be resumed')
        previous=json.loads((run/'config.resolved.json').read_text())
        if previous.get('input_identity')!=[{'path':str(p),'size':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns} for p in files]:raise ValueError('Resume input changed; create a new run')
    else:run.mkdir(parents=True,exist_ok=False)
    # Parsing checkpoints are reusable; SQL phases are deliberately rebuilt from those checkpoints.
    lock=run/'.analysis.lock'
    if lock.exists():
        try:owner=int(lock.read_text())
        except ValueError:raise ValueError('Invalid analysis lock; verify no process is active')
        if psutil.pid_exists(owner):raise ValueError('Another process owns this run')
        lock.unlink()
    fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.write(fd,str(os.getpid()).encode());os.close(fd)
    if resume:
        for filename in ['ABORT','CANCEL']:(run/filename).unlink(missing_ok=True)
        for folder in ['normalized','incidents','evidence','access_history','briefs','tmp']:
            if (run/folder).exists():shutil.rmtree(run/folder)
        for filename in ['analysis.duckdb','analysis.duckdb.wal','findings.parquet','incidents.v1.jsonl']:(run/filename).unlink(missing_ok=True)
    config=dict(config)
    config['input_identity']=[{'path':str(p),'size':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns} for p in files]
    progress=Progress(run,job_id,total,callback)
    deadline=time.time()+config['timeout_seconds'] if config['timeout_seconds'] else None
    monitor=Monitor(run,config['min_free_gb'],config['total_memory_gb'],deadline);monitor.thread.start()
    start=time.monotonic();phase_times={};con=None;success=False
    atomic_json(run/'config.resolved.json',config)
    atomic_json(run/'rules.v1.json',{'version':'1.0','rules':RULES,'stage_taxonomy':'unconfirmed'})
    def check():
        if monitor.error:raise ValueError(monitor.error)
        control(run,deadline)
    progress.guard=check
    try:
        audits=[];limits={}
        required=total*config['disk_estimate_multiplier']+config['min_free_gb']*2**30
        atomic_json(run/'resource_plan.v1.json',{'input_bytes':total,'estimated_additional_disk_bytes':int(required),
            'estimate_multiplier':config['disk_estimate_multiplier'],'disk_free_bytes':shutil.disk_usage(run).free,
            'total_memory_budget_gb':config['total_memory_gb'],'database_budget_gb':config['memory_gb'],
            'parse_workers':config['parse_workers'],'limitations':'Disk estimate is conservative guidance, not a guaranteed upper bound. RSS governor is sampled; enforce a container limit for hard memory isolation.'})
        if shutil.disk_usage(run).free<required:raise ValueError('Estimated working/output space exceeds free disk. Move output to a larger volume or adjust disk_estimate_multiplier after measuring this format.')
        if config['preflight_audit']:
            progress['phase']='auditing';progress.publish(True)
            t=time.monotonic()
            for file in files:
                check()
                audit=audit_file(file,check=check);audits.append(audit)
                if audit['excluded_tail_bytes']:
                    if not config['recover_valid_prefix'] and config['fail_on_binary']:
                        atomic_json(run/'input_audit.v1.json',{'sources':audits})
                        raise ValueError('Input has unsupported binary bytes at '+str(audit['first_invalid_byte'])+'. Verify the file, or explicitly request --recover-valid-prefix for partial coverage.')
                    if config['recover_valid_prefix']:limits[str(file)]=audit['processable_prefix_bytes']
                progress.publish(True)
            phase_times['audit_seconds']=time.monotonic()-t
            atomic_json(run/'input_audit.v1.json',{'sources':audits})
        excluded_bytes=sum(a['excluded_tail_bytes'] for a in audits) if config['recover_valid_prefix'] else 0
        progress['excluded_tail_bytes']=excluded_bytes
        progress['coverage_status']='partial_recovery' if excluded_bytes else 'complete'
        progress['analysis_total_bytes']=total-excluded_bytes
        progress['phase']='parsing';progress.publish(True)
        t=time.monotonic();sources=ingest_parallel(files,run,config,progress,limits,deadline);phase_times['ingestion_seconds']=time.monotonic()-t
        check()
        con=duckdb.connect(str(run/'analysis.duckdb'))
        monitor.con=con
        con.execute("SET memory_limit = '"+str(config['memory_gb'])+"GB'")
        con.execute('SET threads = '+str(config['threads']))
        con.execute('SET preserve_insertion_order = false')
        con.execute("SET temp_directory = '"+str(run/'tmp').replace("'","''")+"'")
        con.execute("SET max_temp_directory_size = '"+str(config['spill_gb'])+"GB'")
        t=time.monotonic();prepare(con,run,progress,config);phase_times['normalization_seconds']=time.monotonic()-t
        check();progress['phase']='detecting';progress.publish(True)
        t=time.monotonic();detect(con,run,config,progress);phase_times['detection_correlation_seconds']=time.monotonic()-t
        check();progress['phase']='writing_results';progress.publish(True)
        t=time.monotonic();export_results(con,run,config,job_id,progress);phase_times['export_seconds']=time.monotonic()-t
        check();monitor.con=None;con.close();con=None
        # Explicitly discard duplicate working representations only after exports succeed.
        shutil.rmtree(run/'staging')
        for path in [run/'analysis.duckdb',run/'analysis.duckdb.wal']:
            path.unlink(missing_ok=True)
        if (run/'tmp').exists():shutil.rmtree(run/'tmp')
        manifest={'contract_version':CONTRACT,'job_id':job_id,'generated_at':utcnow(),'status':'completed',
          'sources':sources,'incident_count':progress['incidents_found'],'detection_count':progress['detections_found'],
          'incidents_path':'incidents.v1.jsonl','evidence_path':'evidence/incident_evidence.parquet',
          'access_history_path':'access_history/authentication.parquet','host_observations_path':'access_history/host_observations.parquet',
          'normalized_path':'normalized/events.parquet','findings_path':'findings.parquet',
          'input_completeness':'partial_recovery' if excluded_bytes else ('complete' if not progress['malformed_records'] else 'completed_with_exclusions'),
          'rejected_records':progress['malformed_records'],'rejected_bytes':progress.get('rejected_bytes',0),
          'rejected_records_path':'diagnostics/rejected.jsonl','summary_path':'summary.v1.json','briefs_path':'briefs.v1.jsonl',
          'source_bytes_total':total,'analysis_bytes':total-excluded_bytes,'excluded_tail_bytes':excluded_bytes,'input_audit_path':'input_audit.v1.json' if audits else None,
          'warnings':['Primary source format is official FortiGate telemetry; EDR generator is a secondary regression fixture.',
            'Kill-chain stage taxonomy remains unconfirmed; ATT&CK tactic is provided separately.',
            'Historical authentication is not current permission.'],
          'demo_indicators_enabled':config['demo_indicators']}
        from .presentation import brief
        from .common import load_json,within
        with (run/'incidents.v1.jsonl').open() as entries,(run/'briefs.v1.jsonl').open('w') as brief_output:
            for index,line in enumerate(entries):
                if index%500==0:check()
                entry=json.loads(line)
                brief_output.write(json.dumps(brief(load_json(within(run,entry['bundle_path'])),manifest),ensure_ascii=False)+'\n')
        atomic_json(run/'summary.v1.json',{'status':'completed','coverage':manifest['input_completeness'],
            'input_bytes':total,'scanned_bytes':progress['processed_bytes'],'reused_parse_bytes':progress.get('reused_parse_bytes',0),'parsed_records':progress['records_parsed'],
            'skipped_records':progress['malformed_records'],'skipped_bytes':progress.get('rejected_bytes',0),
            'excluded_tail_bytes':excluded_bytes,'duplicates':progress['duplicate_records'],
            'findings':progress['detections_found'],'candidate_incidents':progress['incidents_found'],
            'timestamp_conflicts':progress.get('timestamp_conflicts',0),
            'next_step':'Open candidate incidents and inspect their evidence. Candidates are not confirmed attacks.'})
        check()
        atomic_json(run/'manifest.v1.json',manifest)
        progress['status']='completed';progress['phase']='completed';progress.publish(True);success=True
    except BaseException as exc:
        (run/'ABORT').touch()
        (run/'manifest.v1.json').unlink(missing_ok=True)
        progress['status']='failed';progress['phase']='cancelled' if isinstance(exc,(RunCancelled,KeyboardInterrupt)) or (run/'CANCEL').exists() else 'failed'
        progress['error']={'code':type(exc).__name__,'message':(monitor.error or str(exc))[:500]}
        atomic_json(run/'partial.v1.json',{'status':progress['phase'],'complete':False,
            'reason':progress['error'],'resume_supported':True,'resume_scope':'Completed parse partitions only; SQL phases restart.',
            'missing':'Detection and export may be incomplete. Do not import this directory as a completed run.'})
        progress.publish(True)
        raise
    finally:
        monitor.con=None
        if con:con.close()
        monitor.finish()
        lock.unlink(missing_ok=True)
        elapsed=time.monotonic()-start
        used=sum(p.stat().st_size for p in run.rglob('*') if p.is_file())
        atomic_json(run/'metrics.v1.json',{'job_id':job_id,'completed':success,'elapsed_seconds':round(elapsed,3),
          'input_bytes':total,'scanned_bytes':progress['processed_bytes'],'rejected_bytes':progress.get('rejected_bytes',0),'rejected_records':progress['malformed_records'],
          'reused_parse_bytes':progress.get('reused_parse_bytes',0),
          'input_mb_per_second':round((progress['processed_bytes']-progress.get('reused_parse_bytes',0))/max(elapsed,.001)/1e6,3),
          'sampled_peak_process_tree_rss_bytes':monitor.peak if monitor.rss_available and monitor.peak>0 else None,
          'os_process_peak_rss_bytes':int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)*(1 if sys.platform=='darwin' else 1024),
          'rss_sample_interval_seconds':.25,
          'peak_temp_bytes_sampled':monitor.peak_temp,'retained_output_bytes':used,'phase_times':phase_times,
          'measurement_limitations':'Sampled RSS may miss spikes and is not container memory accounting. Independently measure container peak for official judging.',
          'hardware':config['hardware'],'settings':{'threads':config['threads'],'database_memory_gb':config['memory_gb']}})
    return dict(progress)
