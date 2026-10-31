"""Evaluate independent truth after detection; this module is never an engine input."""
import json,time
import duckdb
from .common import load_json,within,sql_string
from .analysis import RULES


def evaluate(run,truth_path):
    if truth_path.stat().st_size>16*2**20:raise ValueError('Evaluation truth exceeds 16 MiB limit')
    truth=load_json(truth_path)
    if not isinstance(truth.get('incidents'),list):raise ValueError('Truth requires incidents list')
    con=duckdb.connect()
    try:
        con.execute("SET memory_limit='256MB'");con.execute('SET threads=1')
        con.execute('CREATE TABLE truth(attack VARCHAR,ordinal INT,evidence_id VARCHAR,technique VARCHAR)')
        ids=set()
        for incident in truth['incidents']:
            if not isinstance(incident.get('id'),str) or incident['id'] in ids or not incident.get('steps'):raise ValueError('Truth incidents require unique id and nonempty steps')
            ids.add(incident['id'])
            con.executemany('INSERT INTO truth VALUES (?,?,?,?)',[(incident['id'],i,step['evidence_id'],step.get('technique_id')) for i,step in enumerate(incident['steps'])])
        if not ids:raise ValueError('Truth must include at least one incident')
        con.execute('CREATE TABLE rule_map(rule_id VARCHAR,technique VARCHAR)')
        con.executemany('INSERT INTO rule_map VALUES (?,?)',[(key,rule['technique_id']) for key,rule in RULES.items()])
        con.execute('CREATE VIEW findings AS SELECT * FROM read_parquet('+sql_string(run/'findings.parquet')+')')
        con.execute('CREATE VIEW events AS SELECT evidence_id,timestamp FROM read_parquet('+sql_string(run/'normalized/events.parquet')+')')
        con.execute('CREATE TABLE hits AS SELECT t.*,f.incident_id,f.rule_id,r.technique AS actual_technique FROM truth t JOIN findings f USING(evidence_id) LEFT JOIN rule_map r USING(rule_id)')
        total=con.execute('SELECT count(*) FROM truth').fetchone()[0]
        detected=con.execute('SELECT count(*) FROM (SELECT DISTINCT attack,ordinal FROM hits)').fetchone()[0]
        labelled=con.execute('SELECT count(*) FROM (SELECT DISTINCT attack,ordinal FROM hits WHERE technique IS NOT NULL)').fetchone()[0]
        correct=con.execute('SELECT count(*) FROM (SELECT DISTINCT attack,ordinal FROM hits WHERE technique=actual_technique)').fetchone()[0]
        paths=con.execute('''WITH matched AS (
            SELECT DISTINCT h.attack,h.ordinal,h.incident_id,e.timestamp FROM hits h JOIN events e USING(evidence_id)),
            ordered AS (SELECT *,lag(timestamp) OVER(PARTITION BY attack,incident_id ORDER BY ordinal) AS previous FROM matched),
            sizes AS (SELECT attack,count(*) AS total FROM truth GROUP BY attack),
            reconstructed AS (SELECT o.attack,o.incident_id FROM ordered o JOIN sizes s USING(attack)
              GROUP BY o.attack,o.incident_id HAVING count(*)=max(s.total) AND bool_and(previous IS NULL OR timestamp>previous))
            SELECT count(DISTINCT attack) FROM reconstructed''').fetchone()[0]
        incident_count=load_json(run/'manifest.v1.json')['incident_count']
        matched_incidents=con.execute('SELECT count(DISTINCT incident_id) FROM hits').fetchone()[0]
        metrics=load_json(run/'metrics.v1.json');timings=[]
        with (run/'incidents.v1.jsonl').open() as entries:
            for _,line in zip(range(20),entries):
                row=json.loads(line);start=time.perf_counter();load_json(within(run,row['bundle_path']));timings.append((time.perf_counter()-start)*1000)
        return {'detection_recall':detected/total,'correct_technique_share':correct/labelled if labelled else None,
            'reconstructed_attack_share':paths/len(ids),
            'false_incident_share':(incident_count-matched_incidents)/incident_count if truth.get('complete') is True and incident_count else (0 if truth.get('complete') is True else None),
            'processing_seconds':metrics['elapsed_seconds'],
            'sampled_peak_process_tree_bytes':metrics.get('sampled_peak_process_tree_rss_bytes'),
            'incident_open_max_ms_sample':max(timings) if timings else None,
            'counts':{'truth_steps':total,'detected_steps':detected,'correct_labels':correct,'truth_attacks':len(ids),'reconstructed_attacks':paths,'candidate_incidents':incident_count},
            'limitations':['Only supplied evidence IDs are matched. Truth must be independent of detection.',
                'False alarms are scored only when truth explicitly declares complete=true.',
                'Path score requires every supplied step in one engine incident with strictly increasing timestamps; ties are undetermined.',
                'Incident-open latency samples local JSON reads, not UI/API latency. Process-tree memory may be unavailable; null is not zero.']}
    finally:con.close()
