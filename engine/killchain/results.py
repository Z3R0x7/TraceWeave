from __future__ import annotations
import json
import duckdb
from .common import load_json,within
from .models import IncidentContract,ProgressContract

def incident_entries(run):
    manifest=load_json(run/'manifest.v1.json')
    if manifest.get('contract_version')!='1.0':raise ValueError('Unsupported contract version')
    with within(run,manifest['incidents_path']).open() as f:
        for line in f:yield json.loads(line)

def get_incident(run,iid):
    if not iid.startswith('inc_') or not iid[4:].isalnum():raise ValueError('Invalid incident ID')
    path=within(run,'incidents/'+iid+'.json')
    if not path.is_file():raise ValueError('Incident not found')
    return load_json(path)

def evidence(run,eid):
    con=duckdb.connect()
    try:
        con.execute("SET memory_limit='256MB'");con.execute('SET threads=1')
        cur=con.execute('''SELECT * FROM read_parquet(?) WHERE evidence_id=? LIMIT 1''',
          [str(within(run,'normalized/events.parquet')),eid])
        columns=[x[0] for x in cur.description];row=cur.fetchone()
        if not row:raise ValueError('Evidence not found')
        return dict(zip(columns,row))
    finally:con.close()

def validate_run(run):
    manifest=load_json(run/'manifest.v1.json')
    if manifest.get('status')!='completed':raise ValueError('Run is not completed')
    for key in ['incidents_path','evidence_path','normalized_path','access_history_path','host_observations_path','findings_path']:
        if not within(run,manifest[key]).is_file():raise ValueError('Missing '+key)
    import tempfile
    import pyarrow as pa
    temporary=tempfile.TemporaryDirectory(prefix='traceweave-validate-')
    from pathlib import Path
    con=duckdb.connect(str(Path(temporary.name)/'validation.duckdb'))
    count=0;citations=[]
    con.execute('CREATE TABLE citations(incident_id VARCHAR,evidence_id VARCHAR)')
    def flush_citations():
        if citations:
            con.register('citation_batch',pa.Table.from_pylist(citations))
            con.execute('INSERT INTO citations SELECT * FROM citation_batch')
            con.unregister('citation_batch');citations.clear()
    try:
        con.execute("SET memory_limit='256MB'");con.execute('SET threads=1')
        con.execute('CREATE VIEW evidence AS SELECT * FROM read_parquet('+"'"+str(within(run,manifest['evidence_path'])).replace("'","''")+"')")
        for entry in incident_entries(run):
            bundle=load_json(within(run,entry['bundle_path']));IncidentContract.model_validate(bundle);count+=1
            if bundle['incident_id']!=entry['incident_id']:raise ValueError('Incident ID mismatch')
            entities={x['entity_id'] for x in bundle['entities']};steps={x['step_id'] for x in bundle['steps']}
            cited=set()
            for step in bundle['steps']:
                if not step['evidence_ids']:raise ValueError('Step missing evidence')
                if step.get('host_id') and step['host_id'] not in entities:raise ValueError('Unknown host entity')
                if step.get('account_id') and step['account_id'] not in entities:raise ValueError('Unknown account entity')
                cited.update(step['evidence_ids'])
            for edge in bundle['edges']:
                if not edge['evidence_ids']:raise ValueError('Edge missing evidence')
                for key in ['source_id','target_id']:
                    if key in edge and edge[key] not in entities:raise ValueError('Unknown edge entity')
                for key in ['source_step_id','target_step_id']:
                    if key in edge and edge[key] not in steps:raise ValueError('Unknown edge step')
                cited.update(edge['evidence_ids'])
            citations.extend({'incident_id':entry['incident_id'],'evidence_id':eid} for eid in cited)
            if len(citations)>=4096:flush_citations()
        flush_citations()
        if con.execute('SELECT 1 FROM citations c ANTI JOIN evidence e ON c.incident_id=e.incident_id AND c.evidence_id=e.evidence_id LIMIT 1').fetchone():raise ValueError('Dangling evidence references')
        if count!=manifest['incident_count']:raise ValueError('Incident count mismatch')
        progress=load_json(run/'progress.v1.json');ProgressContract.model_validate(progress)
        if progress['records_read']!=progress['records_parsed']+progress['malformed_records']:raise ValueError('Record accounting mismatch')
        return {'valid':True,'incident_count':count,'input_completeness':manifest['input_completeness']}
    finally:
        con.close();temporary.cleanup()


def raw_evidence(run,file_id,offset,lines=1):
    """Only registered immutable sources; no caller-provided filesystem path."""
    from pathlib import Path
    if isinstance(offset,bool) or offset<0 or not 1<=lines<=100:raise ValueError('offset must be nonnegative; lines must be 1..100')
    manifest=load_json(run/'manifest.v1.json')
    matches=[source for source in manifest['sources'] if source['source_file_id']==file_id]
    if len(matches)!=1:raise ValueError('Unknown source file ID')
    source=matches[0];path=Path(source['source_file']);stat=path.stat()
    if stat.st_size!=source['size_bytes'] or stat.st_mtime_ns!=source['mtime_ns']:raise ValueError('Source changed since analysis')
    if offset>=stat.st_size:raise ValueError('Offset outside source')
    remaining=65536;records=[]
    with path.open('rb') as handle:
        if offset:
            handle.seek(offset-1)
            if handle.read(1)!=b'\n':raise ValueError('Offset must be a record boundary')
        handle.seek(offset)
        for _ in range(lines):
            start=handle.tell();raw=handle.readline(remaining+1)
            if not raw:break
            if len(raw)>remaining:raise ValueError('Raw evidence exceeds 64 KiB response limit')
            remaining-=len(raw)
            try:text=raw.decode('utf-8')
            except UnicodeDecodeError:text=None
            records.append({'byte_offset':start,'byte_length':len(raw),'text':text,'encoding':'utf8' if text is not None else 'unsupported_binary'})
            if not remaining:break
    return {'source_file_id':file_id,'records':records}
