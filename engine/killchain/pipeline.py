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
from .ingest import inputs, ingest
from .analysis import prepare,detect,export_results,RULES

class Progress(dict):
    def __init__(self,run,job_id,total,callback=None):
        super().__init__(contract_version=CONTRACT,job_id=job_id,status='running',phase='starting',
          processed_bytes=0,total_bytes=total,records_read=0,records_parsed=0,malformed_records=0,
          missing_critical_fields=0,unknown_event_types=0,duplicate_records=0,out_of_order_records=0,
          detections_found=0,incidents_found=0,updated_at=utcnow(),error=None)
        self.run=run;self.callback=callback;self.last=0
    def publish(self,force=False):
        now=time.monotonic()
        if not force and now-self.last<.5:return
        self['updated_at']=utcnow();atomic_json(self.run/'progress.v1.json',self)
        if self.callback:self.callback(dict(self))
        self.last=now

class Monitor:
    def __init__(self,run,min_free_gb):
        self.run=run;self.min_free=min_free_gb*2**30;self.peak=0;self.peak_temp=0;self.error=None;self.rss_available=False
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
            except (OSError,psutil.Error):pass
            self.stop.wait(.25)
    def finish(self):
        self.stop.set();self.thread.join(timeout=2)

def analyze(input_path,output_path,job_id,config,callback=None):
    source=Path(input_path).resolve();run=Path(output_path).resolve()
    if source.is_dir() and (run==source or run.is_relative_to(source)):
        raise ValueError('Output directory must be outside the input directory')
    files=inputs(source); total=sum(p.stat().st_size for p in files)
    if config['hardware']['disk_free_gb']<config['min_free_gb']:
        raise ValueError('Insufficient disk reserve before start')
    run.mkdir(parents=True,exist_ok=False)
    progress=Progress(run,job_id,total,callback)
    monitor=Monitor(run,config['min_free_gb']);monitor.thread.start()
    start=time.monotonic();phase_times={};con=None;success=False
    atomic_json(run/'config.resolved.json',config)
    atomic_json(run/'rules.v1.json',{'version':'1.0','rules':RULES,'stage_taxonomy':'unconfirmed'})
    def check():
        if monitor.error:raise ValueError(monitor.error)
    try:
        progress['phase']='parsing';progress.publish(True)
        t=time.monotonic();sources=ingest(files,run,config,progress);phase_times['ingestion_seconds']=time.monotonic()-t
        check()
        con=duckdb.connect(str(run/'analysis.duckdb'))
        con.execute("SET memory_limit = '"+str(config['memory_gb'])+"GB'")
        con.execute('SET threads = '+str(config['threads']))
        con.execute('SET preserve_insertion_order = false')
        con.execute("SET temp_directory = '"+str(run/'tmp').replace("'","''")+"'")
        con.execute("SET max_temp_directory_size = '"+str(config['spill_gb'])+"GB'")
        t=time.monotonic();prepare(con,run,progress);phase_times['normalization_seconds']=time.monotonic()-t
        check();progress['phase']='detecting';progress.publish(True)
        t=time.monotonic();detect(con,run,config,progress);phase_times['detection_correlation_seconds']=time.monotonic()-t
        check();progress['phase']='writing_results';progress.publish(True)
        t=time.monotonic();export_results(con,run,config,job_id,progress);phase_times['export_seconds']=time.monotonic()-t
        check();con.close();con=None
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
          'input_completeness':'complete' if not progress['malformed_records'] else 'completed_with_exclusions',
          'warnings':['No guarantee of planted attack reconstruction from independent random generator events.',
            'Kill-chain stage taxonomy remains unconfirmed; ATT&CK tactic is provided separately.',
            'Historical authentication is not current permission.'],
          'demo_indicators_enabled':config['demo_indicators']}
        atomic_json(run/'manifest.v1.json',manifest)
        progress['status']='completed';progress['phase']='completed';progress.publish(True);success=True
    except BaseException as exc:
        progress['status']='failed';progress['error']={'code':type(exc).__name__,'message':str(exc)[:500]}
        progress.publish(True)
        raise
    finally:
        if con:con.close()
        monitor.finish()
        elapsed=time.monotonic()-start
        used=sum(p.stat().st_size for p in run.rglob('*') if p.is_file())
        atomic_json(run/'metrics.v1.json',{'job_id':job_id,'completed':success,'elapsed_seconds':round(elapsed,3),
          'input_bytes':total,'input_mb_per_second':round(total/max(elapsed,.001)/1e6,3),
          'sampled_peak_process_tree_rss_bytes':monitor.peak if monitor.rss_available and monitor.peak>0 else None,
          'os_process_peak_rss_bytes':int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)*(1 if sys.platform=='darwin' else 1024),
          'rss_sample_interval_seconds':.25,
          'peak_temp_bytes_sampled':monitor.peak_temp,'retained_output_bytes':used,'phase_times':phase_times,
          'measurement_limitations':'Sampled RSS may miss spikes and is not container memory accounting. Independently measure container peak for official judging.',
          'hardware':config['hardware'],'settings':{'threads':config['threads'],'database_memory_gb':config['memory_gb']}})
    return dict(progress)
