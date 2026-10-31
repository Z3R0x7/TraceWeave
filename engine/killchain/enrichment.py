"""Offline, attributed enrichment; matches are not verdicts or response execution."""
from datetime import datetime,timezone
import ipaddress
from .common import load_json


def load_indicators(path):
    if not path:return None
    data=load_json(path)
    if not isinstance(data,dict) or not all(isinstance(data.get(k),str) and data[k] for k in ['source','retrieved_at']):raise ValueError('Indicator snapshot requires source and retrieved_at')
    try:
        stamp=datetime.fromisoformat(data['retrieved_at'].replace('Z','+00:00'))
        if stamp.tzinfo is None:raise ValueError()
    except ValueError:raise ValueError('Indicator retrieved_at must be timezone-qualified ISO time') from None
    if stamp>datetime.now(timezone.utc):raise ValueError('Indicator snapshot date is in the future')
    records=data.get('indicators')
    if not isinstance(records,list):raise ValueError('Indicator snapshot requires indicators list')
    seen=set();clean=[]
    for item in records:
        if not isinstance(item,dict) or item.get('type') not in {'ip','domain'} or not isinstance(item.get('value'),str):raise ValueError('Supported indicators: ip or domain, with string value')
        value=item['value'].lower().rstrip('.')
        if item['type']=='ip':
            try:value=str(ipaddress.ip_address(value))
            except ValueError:raise ValueError('Invalid indicator IP') from None
        elif not value or len(value)>253 or any(c in value for c in '/: \t\n'):raise ValueError('Invalid indicator domain')
        key=(item['type'],value)
        if key not in seen:clean.append({'type':key[0],'value':key[1]});seen.add(key)
    return {'source':data['source'],'retrieved_at':data['retrieved_at'],'indicators':clean,'_lookup':seen}


def load_playbooks(path):
    if not path:return None
    data=load_json(path)
    if not isinstance(data,dict) or not isinstance(data.get('source'),str) or not isinstance(data.get('retrieved_at'),str) or not isinstance(data.get('techniques'),dict):raise ValueError('Playbook snapshot requires source, retrieved_at and techniques object')
    try:
        stamp=datetime.fromisoformat(data['retrieved_at'].replace('Z','+00:00'))
        if stamp.tzinfo is None or stamp>datetime.now(timezone.utc):raise ValueError()
    except ValueError:raise ValueError('Playbook retrieved_at must be a past timezone-qualified ISO time') from None
    for technique,actions in data['techniques'].items():
        if not technique.startswith('T') or not isinstance(actions,list):raise ValueError('Invalid playbook technique')
        for action in actions:
            if not isinstance(action,dict) or not all(isinstance(action.get(k),str) and action[k] for k in ['id','name','description']):raise ValueError('Playbook mitigation requires id, name, description')
    return data


def match_records(rows,snapshot):
    if not snapshot:return []
    indicators=snapshot['_lookup'];found=[]
    for row in rows:
        values=[('ip',row.get('source_ip')),('ip',row.get('destination_ip')),('domain',row.get('destination_domain'))]
        for kind,value in values:
            if value and (kind,value.lower().rstrip('.')) in indicators:
                found.append({'type':kind,'value':value,'evidence_ids':[row['evidence_id']],
                    'source':snapshot['source'],'snapshot_date':snapshot['retrieved_at'],'interpretation_status':'observed',
                    'meaning':'Exact offline indicator match; not proof of compromise. Snapshot may be stale.'})
    return found


def response_cards(techniques,playbooks,steps=()):
    if not playbooks:return []
    citations={t:sorted({eid for step in steps if step.get('technique_id')==t for eid in step['evidence_ids']}) for t in techniques}
    return [{'technique_id':t,'evidence_ids':citations[t][:100],'evidence_ids_truncated':len(citations[t])>100,'mitigations':playbooks['techniques'][t],
             'source':playbooks['source'],'snapshot_date':playbooks['retrieved_at'],
             'interpretation_status':'hypothesized','meaning':'Analyst guidance for a mapped technique, not evidence that compromise occurred. No actions executed.'}
        for t in techniques if t in playbooks['techniques']]
