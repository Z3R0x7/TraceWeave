"""Source adapters. Format detection never uses reference/ground-truth manifests."""
from datetime import datetime,timezone,timedelta
import json
import re

PAIR=re.compile(r'([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|([^\s"]+))')

def parse_key_values(line):
    fields={};end=0
    for match in PAIR.finditer(line):
        if line[end:match.start()].strip():raise ValueError('invalid_key_value_record')
        key,quoted,bare=match.groups()
        if key in fields:raise ValueError('duplicate_key_value_field')
        fields[key]=(re.sub(r'\\(["\\])',r'\1',quoted) if '\\' in quoted else quoted) if quoted is not None else bare
        end=match.end()
    if not fields or line[end:].strip():raise ValueError('invalid_key_value_record')
    return fields

def firewall_event(fields):
    local=None;epoch=None
    if fields.get('date') and fields.get('time') and fields.get('tz'):
        try:local=datetime.fromisoformat(fields['date']+'T'+fields['time']+fields['tz']).astimezone(timezone.utc)
        except ValueError:raise ValueError('invalid_firewall_local_timestamp') from None
    if fields.get('eventtime'):
        try:
            n=int(fields['eventtime']);digits=len(fields['eventtime'].lstrip('-'))
            scale=10**9 if digits>=18 else (10**6 if digits>=15 else (1000 if digits>=12 else 1))
            seconds,fraction=divmod(n,scale)
            epoch=datetime.fromtimestamp(seconds,timezone.utc)+timedelta(microseconds=fraction*1000000//scale)
        except (ValueError,OverflowError,OSError):raise ValueError('invalid_firewall_eventtime') from None
    stamp=epoch or local
    if stamp is None:raise ValueError('missing_timestamp')
    action=fields.get('action')
    if not action:raise ValueError('missing_event_action')
    auth=action in {'login','ssl-login','auth','authentication'} or 'login' in fields.get('logdesc','').lower()
    category='authentication' if auth else ('network' if fields.get('srcip') or fields.get('dstip') else 'system')
    status=fields.get('status','').lower()
    outcome='failure' if status in {'failed','failure','fail'} else ('success' if status in {'success','successful','succeeded'} else None)
    observer=fields.get('devid') or fields.get('devname')
    # The firewall is an observer, NOT the originating endpoint for traffic records.
    host=fields.get('devname') or observer if auth else None
    user=fields.get('user')
    sent=int(fields.get('sentbyte',0)) if fields.get('sentbyte','0').isdigit() else 0
    received=int(fields.get('rcvdbyte',0)) if fields.get('rcvdbyte','0').isdigit() else 0
    return {'_parsed_timestamp':stamp,'@timestamp':stamp.isoformat(),'event':{'category':[category],'action':action,'outcome':outcome},
      'host':{'name':host},'user':{'name':user},
      'source':{'ip':fields.get('srcip'),'port':fields.get('srcport')},
      'destination':{'ip':fields.get('dstip'),'port':fields.get('dstport'),'domain':fields.get('hostname')},
      'network':{'bytes':sent+received},
      '_firewall':{'observer_name':fields.get('devname'),'observer_id':observer,'source_port':fields.get('srcport'),
         'network_protocol':fields.get('proto'),'network_session_id':fields.get('sessionid'),
         'firewall_type':fields.get('type'),'firewall_subtype':fields.get('subtype'),'firewall_action':action,
         'signature_name':fields.get('attack') or fields.get('virus'),'signature_id':fields.get('attackid'),
         'severity_label':fields.get('severity') or fields.get('level'),'log_message':fields.get('msg'),
         'timestamp_source':'eventtime' if epoch else 'date_time_tz',
         'timestamp_conflict_seconds':abs((epoch-local).total_seconds()) if epoch and local else None,
         'recorded_local_timestamp':' '.join(fields.get(k,'') for k in ['date','time','tz']),
         'recorded_eventtime':fields.get('eventtime'),'original_fields':fields}}

def decode_record(raw,input_format='auto'):
    try:line=raw.decode('utf-8').strip()
    except UnicodeError:raise ValueError('unsupported_binary_record') from None
    if '\x00' in line:raise ValueError('unsupported_binary_record')
    kind=input_format
    if kind=='auto':kind='jsonl' if line.startswith(('{','[')) else 'fortigate'
    if kind=='jsonl':
        return json.loads(line,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json_constant'))),'ecs_jsonl'
    if kind=='fortigate':return firewall_event(parse_key_values(line)),'fortigate_kv'
    raise ValueError('unsupported_input_format')
