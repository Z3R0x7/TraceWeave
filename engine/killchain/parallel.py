"""Newline-aligned, restartable parsing. Workers return counters, never log rows."""
from __future__ import annotations
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
from collections import Counter
import hashlib
import json
import multiprocessing
from pathlib import Path
import shutil
import time
import pyarrow as pa
import pyarrow.parquet as pq
from .common import atomic_json,load_json,digest
from .ingest import SCHEMA,stream_records,normalize
from .log_formats import decode_record


class RunCancelled(RuntimeError):pass


def control(run,deadline=None):
    if (run/'CANCEL').exists() or (run/'ABORT').exists():raise RunCancelled('Run cancelled; completed parse partitions are preserved for resume')
    if deadline and time.time()>deadline:raise TimeoutError('Run timeout reached; completed parse partitions are preserved for resume')


def ranges(path,chunk_bytes,end=None,check=None):
    """No lost/overlapping lines, including lines much larger than a partition."""
    end=path.stat().st_size if end is None else end
    start=0
    with path.open('rb') as source:
        while start<end:
            if check:check()
            stop=min(end,start+chunk_bytes)
            if stop<end:
                source.seek(stop-1)
                if source.read(1)!=b'\n':
                    source.seek(stop)
                    while stop<end:
                        if check:check()
                        block=source.read(min(65536,end-stop))
                        if not block:break
                        newline=block.find(b'\n')
                        stop+=len(block) if newline<0 else newline+1
                        if newline>=0:break
            yield start,stop
            start=stop


def parse_partition(job):
    source,run,start,stop,config,source_meta,deadline,fingerprint=job
    source=Path(source);run=Path(run)
    key=digest(json.dumps([str(source),start,stop,fingerprint],sort_keys=True))
    folder=run/'staging'/key
    marker=folder/'complete.json'
    if marker.exists():
        value=load_json(marker)
        if value['source_meta']==source_meta and value['fingerprint']==fingerprint:
            parts=list(folder.glob('part-*.parquet'))
            if len(parts)==value['part_count'] and all(p.stat().st_size>0 for p in parts):return dict(value,reused=True)
    if folder.exists():shutil.rmtree(folder)
    folder.mkdir(parents=True)
    stats=Counter();batch=[];batch_bytes=0;part=0
    source_id=source_meta['source_file_id']
    max_bytes=int(config['max_record_mb']*2**20)
    def flush():
        nonlocal batch,batch_bytes,part
        if batch:
            pq.write_table(pa.Table.from_pylist(batch,schema=SCHEMA),folder/f'part-{part:07d}.parquet',compression='zstd',row_group_size=10000)
            part+=1;batch=[];batch_bytes=0
        if shutil.disk_usage(run).free<config['min_free_gb']*2**30:raise ValueError('Disk reserve reached while parsing; add disk or move output and resume')
        control(run,deadline)
        atomic_json(folder/'progress.json',dict(stats))
    check_counter=0
    def reader_check():
        nonlocal check_counter
        check_counter+=1
        if check_counter%1000==0:control(run,deadline)
    with (folder/'rejected.jsonl').open('w') as rejected:
        for number,offset,length,raw,error in stream_records(source,max_bytes,stop,start_bytes=start,check=reader_check):
            stats['records_read']+=1;stats['processed_bytes']+=length
            if stats['records_read']%1000==0:control(run,deadline)
            if not error:
                try:
                    event,fmt=decode_record(raw,config['input_format'])
                    # A range-local line number is not a whole-file line number. Byte pointers are exact.
                    row=normalize(event,raw,source,source_id,number if start==0 else None,offset,fmt)
                except (ValueError,TypeError,UnicodeError,RecursionError,OverflowError) as exc:
                    known={'record_not_object','missing_timestamp','invalid_timestamp','timestamp_requires_timezone','missing_event_action','unsupported_binary_record','invalid_key_value_record','duplicate_key_value_field','invalid_firewall_local_timestamp','invalid_firewall_eventtime'}
                    error=str(exc) if str(exc) in known else 'invalid_json_or_fields'
            if error:
                stats['malformed_records']+=1;stats['rejected_bytes']+=length
                if error=='unsupported_binary_record':stats['binary_records']+=1
                stats['error_'+error]+=1
                rejected.write(json.dumps({'source_file':str(source),'byte_offset':offset,'byte_length':length,'range_record':number,'reason':error})+'\n')
                if error=='unsupported_binary_record' and config['fail_on_binary']:raise ValueError(f'Unsupported binary record at byte {offset}; use --corrupt-policy skip for reported exclusions')
            else:
                stats['records_parsed']+=1
                if not row['host_name'] and not row['observer_id']:stats['missing_critical_fields']+=1
                if row['timestamp_conflict_seconds'] and row['timestamp_conflict_seconds']>1:stats['timestamp_conflicts']+=1
                stats[fmt+'_records']+=1
                if row['event_category'] not in {'process','network','authentication','file','registry','system'}:stats['unknown_event_types']+=1
                batch.append(row)
                # Bound raw and retained row estimates independently (tiny lines can expand).
                batch_bytes+=max(length,512+sum(len(v) for v in row.values() if isinstance(v,str)))
                if len(batch)>=config['batch_records'] or batch_bytes>=config['batch_bytes_mb']*2**20:flush()
        flush()
    if not part:
        pq.write_table(pa.Table.from_pylist([],schema=SCHEMA),folder/'part-0000000.parquet');part=1
    after=source.stat()
    if after.st_size!=source_meta['size_bytes'] or after.st_mtime_ns!=source_meta['mtime_ns']:raise ValueError('Input changed during parsing; use a stable snapshot')
    result={'source_meta':source_meta,'fingerprint':fingerprint,'start':start,'stop':stop,'part_count':part,'stats':dict(stats)}
    atomic_json(marker,result)
    return result


def ingest_parallel(files,run,config,progress,limits=None,deadline=None):
    (run/'staging').mkdir(exist_ok=True)
    counters=Counter();manifests=[];completed=0
    fingerprint=digest('parser-v3|'+json.dumps({k:config[k] for k in ['input_format','max_record_mb','batch_records','batch_bytes_mb','fail_on_binary']},sort_keys=True))
    state={'fingerprint':fingerprint,'chunk_mb':config['chunk_mb'],
        'sources':[{'source_file':str(p),'size':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns} for p in files],
        'limits':limits or {}}
    state_path=run/'ingestion_checkpoint.v1.json'
    if state_path.exists() and load_json(state_path)!=state:raise ValueError('Parse settings or source changed; start a new run instead of mixing checkpoints')
    atomic_json(state_path,state)
    def jobs():
        for source in files:
            stat=source.stat();meta={'source_file':str(source),'size_bytes':stat.st_size,'mtime_ns':stat.st_mtime_ns}
            meta['source_file_id']=digest(json.dumps(meta,sort_keys=True),64)
            manifests.append(meta)
            for start,stop in ranges(source,int(config['chunk_mb']*2**20),(limits or {}).get(str(source)),check=lambda:control(run,deadline)):
                yield (str(source),str(run),start,stop,config,meta,deadline,fingerprint)
    def accept(value):
        nonlocal completed
        counters.update(value['stats']);completed+=1
        if value.get('reused'):counters['reused_parse_bytes']+=value['stats'].get('processed_bytes',0)
        for key,value in counters.items():progress[key]=value
        progress['parse_partitions_completed']=completed
        progress.publish()
    iterator=iter(jobs())
    if config['parse_workers']==1 or sum(p.stat().st_size for p in files)<=config['chunk_mb']*2**20:
        for job in iterator:
            control(run,deadline);accept(parse_partition(job))
    else:
        # At most 2*N futures and N bounded batches in memory, independent of source size.
        with ProcessPoolExecutor(max_workers=config['parse_workers'],mp_context=multiprocessing.get_context('spawn')) as pool:
            pending=set()
            try:
                exhausted=False
                while pending or not exhausted:
                    control(run,deadline)
                    while len(pending)<config['parse_workers']*2 and not exhausted:
                        try:pending.add(pool.submit(parse_partition,next(iterator)))
                        except StopIteration:exhausted=True
                    done,pending=wait(pending,timeout=.25,return_when=FIRST_COMPLETED) if pending else (set(),set())
                    for future in done:accept(future.result())
                    progress.publish()
            except BaseException:
                (run/'ABORT').touch()
                for future in pending:future.cancel()
                raise
    # Flatten rejected diagnostics by streaming; retain per-partition files for resume.
    diagnostics=run/'diagnostics';diagnostics.mkdir(exist_ok=True)
    with (diagnostics/'rejected.jsonl').open('wb') as output:
        for file in sorted((run/'staging').glob('*/rejected.jsonl')):
            with file.open('rb') as source:shutil.copyfileobj(source,output,1024*1024)
    if not completed:
        folder=run/'staging'/'empty';folder.mkdir(exist_ok=True)
        pq.write_table(pa.Table.from_pylist([],schema=SCHEMA),folder/'part-0000000.parquet')
    return manifests
