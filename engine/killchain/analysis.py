from __future__ import annotations
import json
from .common import sql_string, atomic_json, digest, iso, CONTRACT

RULES = {
 'office_powershell': {'technique_id':'T1059.001','name':'PowerShell','tactic':'Execution','severity':'high','summary':'Office application launched PowerShell','basis':'raw_event','limitation':'Execution is observed; attacker intent is not established.'},
 'autorun_script': {'technique_id':'T1547.001','name':'Registry Run Keys / Startup Folder','tactic':'Persistence','severity':'high','summary':'Scripting engine modified a user autorun key','basis':'raw_event','limitation':'A persistence mechanism is observed; authorization is unknown.'},
 'configured_destination': {'technique_id':None,'name':None,'tactic':None,'severity':'medium','summary':'Outbound connection matched a configured indicator','basis':'configured_indicator','limitation':'An indicator match alone does not prove command and control or periodic beaconing.'},
 'reported_failures': {'technique_id':'T1110','name':'Brute Force','tactic':'Credential Access','severity':'medium','summary':'Upstream summary reports repeated authentication failures','basis':'upstream_summary','limitation':'The reported count was not reconstructed from individual login records.'},
 'reported_renames': {'technique_id':'T1486','name':'Data Encrypted for Impact','tactic':'Impact','severity':'high','summary':'Upstream summary reports a mass rename pattern','basis':'upstream_summary','limitation':'Technique is a hypothesis; file renaming alone does not prove encryption.'},
 'failures_then_success': {'technique_id':'T1110','name':'Brute Force','tactic':'Credential Access','severity':'high','summary':'Repeated authentication failures followed by a success','basis':'temporal_sequence','limitation':'Sequence is observed; unauthorized credential use remains an interpretation.'},
}

def prepare(con,run,progress):
    raw=str(run/'staging/*.parquet')
    con.execute(f'CREATE VIEW staged AS SELECT * FROM read_parquet({sql_string(raw)})')
    progress['phase']='normalizing';progress.publish()
    con.execute('CREATE TABLE events AS SELECT * EXCLUDE (_rn) FROM (SELECT *, row_number() OVER (PARTITION BY evidence_id ORDER BY source_file, byte_offset) AS _rn FROM staged) WHERE _rn=1')
    unique=con.execute('SELECT count(*) FROM events').fetchone()[0]
    progress['duplicate_records']=progress['records_parsed']-unique
    progress['unique_records']=unique
    con.execute('CREATE TABLE conflicting_event_ids AS SELECT original_event_id, count(*) AS variants FROM events WHERE original_event_id IS NOT NULL GROUP BY original_event_id HAVING count(*)>1')
    progress['conflicting_event_ids']=con.execute('SELECT count(*) FROM conflicting_event_ids').fetchone()[0]
    normalized=run/'normalized';normalized.mkdir()
    con.execute(f'COPY events TO {sql_string(normalized/"events.parquet")} (FORMAT PARQUET, COMPRESSION ZSTD)')
    con.execute('DROP VIEW staged')
    # Keep the analytical table for detection; the persistent DB is removed after successful export.
    return unique

def detect(con,run,config,progress):
    con.execute('CREATE TABLE detections(evidence_id VARCHAR, rule_id VARCHAR, supporting_count BIGINT)')
    def add(rule,predicate):
        con.execute('INSERT INTO detections SELECT evidence_id, ?, 1 FROM events WHERE '+predicate,[rule])
    add('office_powershell',"event_category='process' AND lower(process_name) IN ('powershell.exe','pwsh.exe','pwsh') AND lower(parent_process_name) IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe')")
    add('autorun_script',"event_category='registry' AND contains(lower(registry_path), 'currentversion') AND (contains(lower(registry_path), '\\run\\') OR ends_with(lower(registry_path), '\\run') OR contains(lower(registry_path), '\\runonce\\')) AND lower(process_name) IN ('powershell.exe','pwsh.exe','wscript.exe','cscript.exe')")
    add('reported_failures',f"event_category='authentication' AND reported_failed_count >= {config['failure_threshold']}")
    add('reported_renames',f"event_category='file' AND event_action='file_rename' AND reported_rename_count >= {config['reported_rename_threshold']}")
    ips=list(config['indicator_ips']); domains=[x.lower().rstrip('.') for x in config['indicator_domains']]
    if config['demo_indicators']:
        ips+=['198.51.100.23','203.0.113.57','192.0.2.88']
        domains+=['suspicious-example-c2.invalid','bad-domain-demo.test','sim-exfil.example']
    predicates=[]
    if ips: predicates.append('destination_ip IN ('+','.join(sql_string(x) for x in ips)+')')
    if domains: predicates.append("rtrim(lower(destination_domain),'.') IN ("+','.join(sql_string(x) for x in domains)+')')
    if predicates: add('configured_destination',"event_category='network' AND ("+' OR '.join(predicates)+')')
    window=config['failure_window_minutes'];threshold=config['failure_threshold']
    con.execute(f'''CREATE TABLE auth_sequences AS
      SELECT * FROM (
       SELECT evidence_id, timestamp, host_name, account_id, source_ip, outcome,
        count(*) FILTER (WHERE outcome='failure') OVER (
          PARTITION BY host_name,account_id,source_ip ORDER BY timestamp
          RANGE BETWEEN INTERVAL '{window} minutes' PRECEDING AND CURRENT ROW) AS failure_count
       FROM events WHERE event_category='authentication' AND host_name IS NOT NULL
          AND account_id IS NOT NULL AND source_ip IS NOT NULL
      ) WHERE outcome='success' AND failure_count >= {threshold}''')
    con.execute("INSERT INTO detections SELECT evidence_id, 'failures_then_success', failure_count FROM auth_sequences")
    # Full supporting membership stays on disk; no enormous list aggregation in Python or SQL.
    con.execute('CREATE TABLE finding_evidence AS SELECT evidence_id AS finding_event_id, rule_id, evidence_id FROM detections')
    con.execute(f'''INSERT INTO finding_evidence
      SELECT s.evidence_id,'failures_then_success',f.evidence_id
      FROM auth_sequences s JOIN events f ON f.event_category='authentication'
       AND f.outcome='failure' AND f.host_name=s.host_name AND f.account_id=s.account_id
       AND f.source_ip=s.source_ip
       AND f.timestamp BETWEEN s.timestamp-INTERVAL '{window} minutes' AND s.timestamp''')
    progress['detections_found']=con.execute('SELECT count(*) FROM detections').fetchone()[0]
    progress['phase']='correlating';progress.publish()
    # Explicit process identity is the only automatic multi-detection grouping in v1.
    # A missing identity yields an individual investigation, not host/time-based invented continuity.
    con.execute('''CREATE TABLE findings AS SELECT
       'inc_' || substr(sha256(CASE WHEN e.process_entity_id IS NOT NULL AND e.host_name IS NOT NULL
          THEN 'process|'||e.host_name||'|'||e.process_entity_id ELSE 'event|'||e.evidence_id END),1,24) AS incident_id,
       'det_' || substr(sha256(d.evidence_id||'|'||d.rule_id),1,24) AS detection_id,
       d.evidence_id,d.rule_id,d.supporting_count,e.timestamp,e.host_name,e.account_id,e.process_entity_id
       FROM detections d JOIN events e USING(evidence_id)''')
    con.execute('''CREATE TABLE incident_summaries AS SELECT incident_id,
      min(timestamp) AS first_seen,max(timestamp) AS last_seen,count(*) AS detection_count,
      CASE WHEN count(*) FILTER (WHERE rule_id IN ('office_powershell','autorun_script','reported_renames','failures_then_success'))>0
        THEN 'high' ELSE 'medium' END AS severity,
      CASE WHEN count(DISTINCT evidence_id)>1 THEN 'related_activity' ELSE 'single_finding' END AS incident_kind
      FROM findings GROUP BY incident_id''')
    progress['incidents_found']=con.execute('SELECT count(*) FROM incident_summaries').fetchone()[0]


def export_results(con,run,config,job_id,progress):
    (run/'incidents').mkdir();(run/'evidence').mkdir();(run/'access_history').mkdir()
    con.execute('''CREATE TABLE evidence_export AS SELECT DISTINCT f.incident_id,e.* FROM findings f
      JOIN finding_evidence m ON m.finding_event_id=f.evidence_id AND m.rule_id=f.rule_id
      JOIN events e ON e.evidence_id=m.evidence_id''')
    con.execute(f'COPY evidence_export TO {sql_string(run/"evidence/incident_evidence.parquet")} (FORMAT PARQUET, COMPRESSION ZSTD)')
    # Successful access history is not a statement of present permissions or compromise.
    con.execute(f'''COPY (SELECT evidence_id,timestamp AS observed_at,account_id AS principal_id,
      host_name AS target_host_name,source_ip,source_file,source_file_id,byte_offset,byte_length,
      'observed_successful_authentication' AS relationship_type,
      'Historical authentication; not proof of current permission or admin rights' AS limitation
      FROM events WHERE event_category='authentication' AND outcome='success')
      TO {sql_string(run/'access_history/authentication.parquet')} (FORMAT PARQUET, COMPRESSION ZSTD)''')
    con.execute(f'COPY (SELECT DISTINCT host_name,host_ip,timestamp AS observed_at,evidence_id FROM events WHERE host_name IS NOT NULL AND host_ip IS NOT NULL) TO {sql_string(run/"access_history/host_observations.parquet")} (FORMAT PARQUET, COMPRESSION ZSTD)')
    con.execute(f'COPY findings TO {sql_string(run/"findings.parquet")} (FORMAT PARQUET, COMPRESSION ZSTD)')
    cursor=con.cursor().execute("""SELECT f.detection_id,f.rule_id,f.supporting_count,f.incident_id,e.*
       FROM findings f JOIN events e USING(evidence_id)
       ORDER BY f.incident_id,e.timestamp,e.evidence_id,f.rule_id""")
    columns=[x[0] for x in cursor.description]
    def records():
        while values:=cursor.fetchmany(1000):
            for value in values: yield dict(zip(columns,value))
    from itertools import groupby
    with (run/'incidents.v1.jsonl').open('w',encoding='utf-8') as out:
        for iid,group in groupby(records(),lambda r:r['incident_id']):
            preview=[];count=0;first=None;last=None;severity='medium';multi=False;initial=None
            for r in group:
                count+=1;first=r['timestamp'] if first is None else first;last=r['timestamp']
                if initial is None: initial=r['evidence_id']
                elif r['evidence_id']!=initial: multi=True
                if RULES[r['rule_id']]['severity']=='high': severity='high'
                if len(preview)<config['max_incident_steps']: preview.append(r)
            summary={'incident_id':iid,'job_id':job_id,'revision':1,'first_seen':iso(first),'last_seen':iso(last),
                     'detection_count':count,'merged_alert_count':count,'severity':severity,
                     'incident_kind':'related_activity' if multi else 'single_finding',
                     'bundle_path':f'incidents/{iid}.json'}
            atomic_json(run/summary['bundle_path'],make_bundle(con,iid,summary,config,preview))
            out.write(json.dumps(summary)+'\n')
            progress.publish()


def make_bundle(con,iid,summary,config,rows_override=None):
    cap=config['max_incident_steps']
    if rows_override is None:
        cursor=con.execute("""SELECT f.detection_id,f.rule_id,f.supporting_count,e.* FROM findings f
           JOIN events e USING(evidence_id) WHERE f.incident_id=?
           ORDER BY e.timestamp,e.evidence_id,f.rule_id LIMIT ?""",[iid,cap])
        columns=[x[0] for x in cursor.description]
        rows_override=[dict(zip(columns,v)) for v in cursor.fetchall()]
    steps=[]; entities={};edges=[];techniques={};prev=None
    for index,r in enumerate(rows_override,1):
        rule=RULES[r['rule_id']]
        ids=[r['evidence_id']]; full_count=1
        if r['rule_id']=='failures_then_success':
            ids=[x[0] for x in con.execute("""SELECT evidence_id FROM finding_evidence
               WHERE finding_event_id=? AND rule_id=? ORDER BY evidence_id LIMIT 100""",[r['evidence_id'],r['rule_id']]).fetchall()]
            full_count=r['supporting_count']+1
        host_id='host:'+r['host_name'] if r['host_name'] else None
        account_id='account:'+r['account_id'] if r['account_id'] else None
        if host_id:entities[host_id]={'entity_id':host_id,'type':'host','label':r['host_name']}
        if account_id:entities[account_id]={'entity_id':account_id,'type':'account','label':r['account_id']}
        step={'step_id':r['detection_id'],'step_index':index,'timestamp':iso(r['timestamp']),
              'summary':rule['summary'],'rule_id':r['rule_id'],'rule_version':'1.0',
              'technique_id':rule['technique_id'],'tactic':rule['tactic'],'kill_chain_stage':None,
              'mapping_status':'hypothesis' if r['rule_id']=='reported_renames' else ('rule_mapping' if rule['technique_id'] else 'unmapped'),
              'host_id':host_id,'account_id':account_id,'primary_evidence_id':r['evidence_id'],
              'evidence_ids':ids,'evidence_count':full_count,'evidence_ids_truncated':full_count>len(ids),
              'evidence_strength':'derived','detection_basis':rule['basis'],'supporting_count':r['supporting_count'],
              'uncertainty_reason':rule['limitation'],'process_entity_id':r['process_entity_id']}
        steps.append(step)
        if rule['technique_id']: techniques[rule['technique_id']]={'id':rule['technique_id'],'name':rule['name'],'tactic':rule['tactic'],'kill_chain_stage':None}
        if host_id and account_id:
            edges.append({'edge_id':'edge_'+digest(step['step_id']+'account'),'source_id':account_id,'target_id':host_id,
               'relationship':'activity_recorded_on','evidence_ids':[r['evidence_id']],'evidence_strength':'observed',
               'reason':'Account and host are attributes of the same source record; not proof of compromise.'})
        if host_id and r['destination_ip']:
            target='ip:'+r['destination_ip'];entities[target]={'entity_id':target,'type':'ip','label':r['destination_ip']}
            edges.append({'edge_id':'edge_'+digest(step['step_id']+'network'),'source_id':host_id,'target_id':target,
              'relationship':'connection_recorded_to','evidence_ids':[r['evidence_id']],'evidence_strength':'observed',
              'reason':'Destination is recorded in the network event; no claim about successful exfiltration.'})
        if prev and r['process_entity_id']:
            edges.append({'edge_id':'edge_'+digest(prev['step_id']+step['step_id']),
              'source_step_id':prev['step_id'],'target_step_id':step['step_id'],'relationship':'same_recorded_process',
              'evidence_ids':[prev['primary_evidence_id'],r['evidence_id']],'evidence_strength':'derived',
              'reason':'Same host-scoped process entity ID. Display order uses timestamps; ties do not establish causality.',
              'ordering':'undetermined' if prev['timestamp']==step['timestamp'] else 'timestamp_order'})
        prev=step
    return {'contract_version':CONTRACT,**summary,'title':('Related suspicious activity' if summary['incident_kind']=='related_activity' else 'Single suspicious finding'),
      'entities':list(entities.values()),'techniques':list(techniques.values()),'steps':steps,'edges':edges,
      'steps_truncated':summary['detection_count']>cap,'total_step_count':summary['detection_count'],
      'stage_taxonomy':'unconfirmed; ATT&CK tactics supplied separately',
      'uncertainties':['Candidate investigation, not a confirmed attack. No inferred missing attack steps.',
        'Stable process identity is required for automatic multi-event grouping in this version.',
        'Presentation tie-breaks do not imply causal order.'],
      'ai_review':{'status':'not_requested'},'evidence_path':'evidence/incident_evidence.parquet',
      'all_steps_query':'Find all detections for this incident in findings.parquet; bounded bundle is a preview.'}
