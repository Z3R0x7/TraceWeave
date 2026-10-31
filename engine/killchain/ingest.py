from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import pyarrow as pa
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
FIELD_NAMES=tuple(SCHEMA.names)

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
    if record_format=='fortigate_kv':return normalize_firewall(event,raw,source,file_id,number,offset)
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
    row=dict.fromkeys(FIELD_NAMES)
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
               evidence_excerpt=(json.dumps(sanitize(event),ensure_ascii=False,separators=(',',':'))[:4096] if record_format!='fortigate_kv' else None))
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


def normalize_firewall(event,raw,source,file_id,number,offset):
    """Direct source mapping avoids dozens of generic nested ECS lookups per log line."""
    extra=event['_firewall'];fields=extra['original_fields'];row=dict.fromkeys(FIELD_NAMES)
    row.update(record_format='fortigate_kv',evidence_id='ev_'+hashlib.sha256(raw.strip()).hexdigest(),
        timestamp=event['_parsed_timestamp'],host_name=event['host']['name'],user_name=fields.get('user'),
        account_id=fields.get('user'),event_category=event['event']['category'][0],event_action=fields['action'],
        outcome=event['event']['outcome'],source_ip=fields.get('srcip'),destination_ip=fields.get('dstip'),
        source_port=integer(fields.get('srcport')),destination_port=integer(fields.get('dstport')),
        destination_domain=fields.get('hostname'),network_bytes=integer(event['network']['bytes']),
        source_file=str(source),source_file_id=file_id,raw_record_number=number,byte_offset=offset,byte_length=len(raw))
    for key in ['observer_name','observer_id','network_protocol','network_session_id','firewall_type',
                'firewall_subtype','firewall_action','signature_name','signature_id','severity_label',
                'log_message','timestamp_source','recorded_local_timestamp','recorded_eventtime','timestamp_conflict_seconds']:
        row[key]=extra.get(key)
    selected={k:sanitize(fields[k]) for k in ['date','time','eventtime','tz','type','subtype','action','status','user','srcip','srcport','dstip','dstport','sessionid','attack','virus','sentbyte','rcvdbyte','msg'] if k in fields}
    row['evidence_excerpt']=json.dumps(selected,ensure_ascii=False,separators=(',',':'))[:4096]
    return row

def inputs(path):
    path=Path(path).resolve()
    if not path.exists(): raise ValueError('Input path does not exist')
    suffixes={'.log','.json','.jsonl','.ndjson'}
    files=[path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file() and not p.is_symlink() and p.suffix.lower() in suffixes and not p.name.endswith('.manifest.json'))
    if not files: raise ValueError('No supported log input files')
    return files

def stream_records(source,max_bytes,stop_bytes=None,start_bytes=0,check=None):
    """Bound one line; drain oversized records in bounded reads."""
    with source.open('rb') as f:
        f.seek(start_bytes)
        number=0
        while True:
            if check:check()
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
                    if check:check()
                    raw=f.readline(max_bytes+1)
                    if not raw: break
                    length+=len(raw)
                yield number,start,length,None,'oversized_record'
            else:
                yield number,start,length,raw,None
