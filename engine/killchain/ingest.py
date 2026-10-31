from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import pyarrow as pa
import pyarrow.parquet as pq
from .common import sanitize
from .log_formats import decode_record

SCHEMA = pa.schema([
    ('record_format',pa.string()),
    ('observer_name',pa.string()),('observer_id',pa.string()),('source_port',pa.int64()),
    ('network_protocol',pa.string()),('network_session_id',pa.string()),
    ('firewall_type',pa.string()),('firewall_subtype',pa.string()),('firewall_action',pa.string()),
    ('signature_name',pa.string()),('signature_id',pa.string()),('severity_label',pa.string()),('log_message',pa.string()),
    ('timestamp_source',pa.string()),('timestamp_conflict_seconds',pa.float64()),
    ('recorded_local_timestamp',pa.string()),('recorded_eventtime',pa.string()),
    ('evidence_id',pa.string()), ('original_event_id',pa.string()),
    ('timestamp',pa.timestamp('us',tz='UTC')), ('host_name',pa.string()), ('host_ip',pa.string()),
    ('user_name',pa.string()), ('account_id',pa.string()), ('event_category',pa.string()),
    ('event_action',pa.string()), ('outcome',pa.string()), ('source_ip',pa.string()),
    ('destination_ip',pa.string()), ('destination_port',pa.int64()), ('destination_domain',pa.string()),
    ('process_entity_id',pa.string()), ('session_id',pa.string()), ('process_pid',pa.int64()),
    ('parent_entity_id',pa.string()), ('process_name',pa.string()), ('parent_process_name',pa.string()),
    ('command_line',pa.string()), ('registry_path',pa.string()), ('file_path',pa.string()),
    ('network_bytes',pa.int64()), ('reported_failed_count',pa.int64()), ('reported_rename_count',pa.int64()),
    ('upstream_kind',pa.string()), ('upstream_technique_id',pa.string()), ('upstream_rule_name',pa.string()),
    ('source_file',pa.string()), ('source_file_id',pa.string()), ('raw_record_number',pa.int64()),
    ('byte_offset',pa.int64()), ('byte_length',pa.int64()), ('evidence_excerpt',pa.string())
])

def get(obj, path, default=None):
    for part in path.split('.'):
        if not isinstance(obj,dict): return default
        obj=obj.get(part)
    return default if obj is None else obj

def text(v):
    if isinstance(v,list): return text(v[0]) if v else None
    return str(v) if isinstance(v,(str,int,float)) and not isinstance(v,bool) else None

def integer(v):
    if isinstance(v,bool): return None
    try:
        x=int(v)
        return x if -(2**63) <= x < 2**63 else None
    except (ValueError,TypeError,OverflowError): return None

def normalize(event, raw, source, file_id, number, offset,record_format="ecs_jsonl"):
    if not isinstance(event,dict): raise ValueError('record_not_object')
    stamp=text(event.get('@timestamp'))
    if not stamp: raise ValueError('missing_timestamp')
    try:
        ts=datetime.fromisoformat(stamp.replace('Z','+00:00'))
    except ValueError: raise ValueError('invalid_timestamp') from None
    if ts.tzinfo is None: raise ValueError('timestamp_requires_timezone')
    ts=ts.astimezone(timezone.utc)
    if not get(event,'event.action'): raise ValueError('missing_event_action')
    user=text(get(event,'user.name'))
    domain=text(get(event,'user.domain'))
    account=((domain+'\\') if domain else '')+user if user else None
    row={field.name:None for field in SCHEMA}
    row.update(evidence_id='ev_'+hashlib.sha256(raw.strip()).hexdigest(),
               original_event_id=text(get(event,'event.id')), timestamp=ts,
               host_name=text(get(event,'host.name')),host_ip=text(get(event,'host.ip')),
               user_name=user,account_id=account,event_category=text(get(event,'event.category')),
               event_action=text(get(event,'event.action')),outcome=text(get(event,'event.outcome')),
               source_ip=text(get(event,'source.ip')),destination_ip=text(get(event,'destination.ip')),
               destination_port=integer(get(event,'destination.port')),destination_domain=text(get(event,'destination.domain')),
               process_entity_id=text(get(event,'process.entity_id')),session_id=text(get(event,'session.id')),
               process_pid=integer(get(event,'process.pid')),parent_entity_id=text(get(event,'process.parent.entity_id')),
               process_name=text(get(event,'process.name')),parent_process_name=text(get(event,'process.parent.name')),
               command_line=text(get(event,'process.command_line')),registry_path=text(get(event,'registry.path')),
               file_path=text(get(event,'file.path')),network_bytes=integer(get(event,'network.bytes')),
               reported_failed_count=integer(get(event,'labels_extra.failed_count_5min')),
               reported_rename_count=integer(get(event,'labels_extra.files_renamed_60s')),
               upstream_kind=text(get(event,'event.kind')),upstream_technique_id=text(get(event,'threat.technique.id')),
               upstream_rule_name=text(get(event,'rule.name')),source_file=str(source),source_file_id=file_id,
               raw_record_number=number,byte_offset=offset,byte_length=len(raw),
               evidence_excerpt=json.dumps(sanitize(event),ensure_ascii=False,separators=(',',':'))[:4096])
    if record_format=='fortigate_kv':
        fields=event.get('_firewall',{}).get('original_fields',{})
        selected={k:fields[k] for k in ['date','time','eventtime','tz','type','subtype','action','status','user','srcip','srcport','dstip','dstport','sessionid','attack','virus','sentbyte','rcvdbyte','msg'] if k in fields}
        row['evidence_excerpt']=json.dumps(sanitize(selected),ensure_ascii=False,separators=(',',':'))[:4096]
    row['record_format']=record_format
    extra=event.get('_firewall',{})
    for key in ['observer_name','observer_id','network_protocol','network_session_id','firewall_type',
                'firewall_subtype','firewall_action','signature_name','signature_id','severity_label',
                'log_message','timestamp_source','recorded_local_timestamp','recorded_eventtime']:
        row[key]=text(extra.get(key))
    row['source_port']=integer(extra.get('source_port',get(event,'source.port')))
    row['timestamp_conflict_seconds']=extra.get('timestamp_conflict_seconds')
    return row

def inputs(path):
    path=Path(path).resolve()
    if not path.exists(): raise ValueError('Input path does not exist')
    suffixes={'.log','.json','.jsonl','.ndjson'}
    files=[path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file() and not p.is_symlink() and p.suffix.lower() in suffixes and not p.name.endswith('.manifest.json'))
    if not files: raise ValueError('No supported log input files')
    return files

def stream_records(source,max_bytes,stop_bytes=None):
    """Bound one line; drain oversized records in bounded reads."""
    with source.open('rb') as f:
        number=0
        while True:
            start=f.tell()
            if stop_bytes is not None and start>=stop_bytes:return
            size=min(max_bytes+1,stop_bytes-start) if stop_bytes is not None else max_bytes+1
            raw=f.readline(size)
            if not raw: return
            number+=1
            length=len(raw)
            oversized=length>max_bytes
            if oversized:
                while not raw.endswith(b'\n'):
                    raw=f.readline(max_bytes+1)
                    if not raw: break
                    length+=len(raw)
                yield number,start,length,None,'oversized_record'
            else:
                yield number,start,length,raw,None

def ingest(files,run,config,progress,limits=None):
    staging=run/'staging'
    staging.mkdir()
    diagnostics=run/'diagnostics'
    diagnostics.mkdir(exist_ok=True)
    batch=[]; batch_bytes=0; batch_id=0
    file_manifests=[]
    limit=int(config['max_record_mb']*2**20)
    def flush():
        nonlocal batch,batch_bytes,batch_id
        if batch:
            pq.write_table(pa.Table.from_pylist(batch,schema=SCHEMA),staging/f'part-{batch_id:07d}.parquet',compression='zstd')
            batch_id+=1;batch=[];batch_bytes=0
        if shutil.disk_usage(run).free < config['min_free_gb']*2**30:
            raise ValueError('Workspace free space fell below configured reserve')
    with (diagnostics/'rejected.jsonl').open('w',encoding='utf-8') as rejected:
        for source in files:
            stat=source.stat(); file_id=hashlib.sha256((str(source)+'|'+str(stat.st_size)+'|'+str(stat.st_mtime_ns)).encode()).hexdigest()
            previous=None
            for number,offset,length,raw,error in stream_records(source,limit,(limits or {}).get(str(source))):
                progress['records_read']+=1;progress['processed_bytes']+=length
                if not error:
                    try:
                        ev,fmt=decode_record(raw,config['input_format'])
                        row=normalize(ev,raw,source,file_id,number,offset,fmt)
                    except (ValueError,TypeError,UnicodeError,RecursionError) as exc:
                        error=str(exc) if str(exc) in {'record_not_object','missing_timestamp','invalid_timestamp','timestamp_requires_timezone','missing_event_action','unsupported_binary_record','invalid_key_value_record','duplicate_key_value_field','invalid_firewall_local_timestamp','invalid_firewall_eventtime'} else 'invalid_json_or_fields'
                if error:
                    progress['malformed_records']+=1
                    rejected.write(json.dumps({'source_file':str(source),'record':number,'byte_offset':offset,'reason':error})+'\n')
                    if error=='unsupported_binary_record' and config['fail_on_binary']:
                        progress.publish(True)
                        raise ValueError(f'Unsupported binary record at byte {offset}; full-input analysis cannot be claimed. Verify file format/integrity.')
                else:
                    progress['records_parsed']+=1
                    if not row['host_name'] and not row['observer_id']: progress['missing_critical_fields']+=1
                    if row['timestamp_conflict_seconds'] and row['timestamp_conflict_seconds']>1:
                        progress['timestamp_conflicts']=progress.get('timestamp_conflicts',0)+1
                    progress[row['record_format']+'_records']=progress.get(row['record_format']+'_records',0)+1
                    if row['event_category'] not in {'process','network','authentication','file','registry','system'}: progress['unknown_event_types']+=1
                    if previous and row['timestamp'] < previous: progress['out_of_order_records']+=1
                    previous=row['timestamp']
                    batch.append(row);batch_bytes+=length
                    if len(batch)>=config['batch_records'] or batch_bytes>=config['batch_bytes_mb']*2**20:
                        flush();progress.publish()
                if progress['records_read']%10000==0: progress.publish()
            now=source.stat()
            if now.st_size!=stat.st_size or now.st_mtime_ns!=stat.st_mtime_ns:
                raise ValueError('Input changed during analysis; use a stable dataset snapshot')
            # Hash is complete only if no record was oversized. Per-file metadata is always preserved.
            file_manifests.append({'source_file':str(source),'source_file_id':file_id,'size_bytes':stat.st_size,'mtime_ns':stat.st_mtime_ns})
    flush()
    if not batch_id:
        pq.write_table(pa.Table.from_pylist([],schema=SCHEMA),staging/'part-0000000.parquet',compression='zstd')
    return file_manifests
