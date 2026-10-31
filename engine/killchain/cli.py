from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
from rich.console import Console
from rich.table import Table
from .common import atomic_json,iso,load_json
from .resources import resolve_config,hardware

console=Console(stderr=True)

def config_overrides(args):
    names=['recover_valid_prefix','input_format','profile','threads','memory_gb','batch_records','spill_gb','min_free_gb','ai_provider','ai_model','ai_max_reviews','demo_indicators']
    return {k:getattr(args,k,None) for k in names if getattr(args,k,None) is not None}

def add_config(p):
    p.add_argument('--config',type=Path)
    p.add_argument('--recover-valid-prefix',action='store_true',default=None,help='Explicitly allow PARTIAL analysis of the verified text prefix; excluded bytes are reported')
    p.add_argument('--input-format',choices=['auto','jsonl','fortigate'],help='Default auto detects each record; official data uses FortiGate key=value')
    p.add_argument('--profile',choices=['auto','conservative','balanced','throughput'])
    p.add_argument('--threads',type=int)
    p.add_argument('--memory-gb',type=float,help='Database budget, not total process memory')
    p.add_argument('--batch-records',type=int)
    p.add_argument('--spill-gb',type=float)
    p.add_argument('--min-free-gb',type=float)
    p.add_argument('--demo-indicators',action='store_true',default=None,help='Explicitly enable generator-only test indicators')
    p.add_argument('--ai-provider',choices=['none','groq','openai'])
    p.add_argument('--ai-model')
    p.add_argument('--ai-max-reviews',type=int)

def parser():
    p=argparse.ArgumentParser(description='Kill Chain Engine: bounded-memory EDR analysis and evidence inspection')
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('menu',help='Interactive setup and run menu')
    d=sub.add_parser('doctor',help='Inspect CPU, memory and storage');d.add_argument('--workspace',type=Path,default=Path('.'))
    c=sub.add_parser('configure',help='Write non-secret configuration interactively');c.add_argument('--output',type=Path,default=Path('config.local.json'))
    au=sub.add_parser('audit',help='Audit the complete file for UTF-8/binary boundaries and SHA-256');au.add_argument('--input',type=Path,required=True)
    i=sub.add_parser('inspect',help='Inspect bounded input samples');i.add_argument('--input',type=Path,required=True);i.add_argument('--limit',type=int,default=20)
    a=sub.add_parser('analyze',help='Analyze a stable line-delimited JSON dataset');a.add_argument('--input',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--job-id');a.add_argument('--quiet',action='store_true');add_config(a)
    l=sub.add_parser('incidents',help='List saved incidents');l.add_argument('--run',type=Path,required=True);l.add_argument('--offset',type=int,default=0);l.add_argument('--limit',type=int,default=20);l.add_argument('--sort',choices=['id','time','severity'],default='id');l.add_argument('--json',action='store_true')
    s=sub.add_parser('show',help='Inspect one saved incident');s.add_argument('--run',type=Path,required=True);s.add_argument('--incident',required=True);s.add_argument('--json',action='store_true')
    e=sub.add_parser('evidence',help='Read normalized evidence and source locator');e.add_argument('--run',type=Path,required=True);e.add_argument('--id',required=True)
    v=sub.add_parser('validate',help='Validate artifacts and evidence references');v.add_argument('--run',type=Path,required=True)
    r=sub.add_parser('review',help='Optional bounded AI review of saved incidents');r.add_argument('--run',type=Path,required=True);r.add_argument('--incident');add_config(r)
    return p

def configure(path):
    if not sys.stdin.isatty():raise ValueError('Configuration prompts require a terminal; use --config and environment variables for automation')
    config={'profile':input('Resource profile [auto/conservative/balanced/throughput] (auto): ').strip() or 'auto'}
    memory=input('Database memory budget in GiB (blank = auto): ').strip()
    if memory:config['memory_gb']=float(memory)
    threads=input('Database threads (blank = auto): ').strip()
    if threads:config['threads']=int(threads)
    provider=input('AI provider [none/groq/openai] (none): ').strip() or 'none';config['ai_provider']=provider
    if provider!='none':
        config['ai_model']=input('Model ID ('+('openai/gpt-oss-120b' if provider=='groq' else 'required')+'): ').strip() or ('openai/gpt-oss-120b' if provider=='groq' else '')
        key=getpass.getpass('API key (hidden; held only in this session; blank uses environment): ')
        if key:os.environ['GROQ_API_KEY' if provider=='groq' else 'OPENAI_API_KEY']=key
    config['demo_indicators']=input('Enable synthetic generator indicators? [y/N]: ').strip().lower()=='y'
    resolve_config(overrides=config)
    if path.exists():raise ValueError('Configuration exists; choose another output path to avoid overwrite')
    atomic_json(path,config);path.chmod(0o600)
    console.print('Saved non-secret configuration. Entered keys are never written. Use the menu to analyze in this session; a later invocation needs an environment key.',markup=False)
    return path

def menu():
    if not sys.stdin.isatty():raise ValueError('Interactive menu requires a terminal; use explicit commands')
    console.print('Kill Chain Engine — script-first investigation',markup=False)
    console.print('1. Check resources\n2. Inspect input\n3. Configure and analyze\n4. List incidents\n5. Show incident',markup=False)
    choice=input('Choose [1-5]: ').strip()
    if choice=='1':return main(['doctor'])
    if choice=='2':return main(['inspect','--input',input('Input file/directory: ').strip()])
    if choice=='3':
        source=input('Input file/directory: ').strip();output=input('New output directory: ').strip()
        from datetime import datetime
        cfg=Path('config-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.local.json')
        configure(cfg)
        return main(['analyze','--input',source,'--output',output,'--config',str(cfg)])
    if choice=='4':return main(['incidents','--run',input('Run directory: ').strip()])
    if choice=='5':return main(['show','--run',input('Run directory: ').strip(),'--incident',input('Incident ID: ').strip()])
    raise ValueError('Select a listed option')

def main(argv=None):
    args=parser().parse_args(argv if argv is not None else (sys.argv[1:] or ['menu']))
    try:
        if args.command=='menu':return menu()
        if args.command=='doctor':print(json.dumps(hardware(args.workspace),indent=2));return 0
        if args.command=='configure':configure(args.output);return 0
        if args.command=='audit':
            from .audit import audit_file
            print(json.dumps(audit_file(args.input),indent=2));return 0
        if args.command=='inspect':
            from .ingest import inputs,stream_records,normalize
            if not 1<=args.limit<=1000:raise ValueError('limit must be between 1 and 1000')
            files=inputs(args.input);sample=[];errors=0;n=0
            for path in files:
                for number,offset,length,raw,error in stream_records(path,2**20):
                    n+=1
                    try:
                        if error:raise ValueError(error)
                        from .log_formats import decode_record
                        event,fmt=decode_record(raw)
                        row=normalize(event,raw,path,'inspection',number,offset,fmt)
                        sample.append({'format':row['record_format'],'category':row['event_category'],'action':row['event_action'],'has_process_identity':bool(row['process_entity_id'])})
                    except (ValueError,TypeError,UnicodeError,RecursionError):errors+=1
                    if n>=args.limit:break
                if n>=args.limit:break
            print(json.dumps({'files':len(files),'total_bytes':sum(p.stat().st_size for p in files),'sampled_records':n,'sample_parse_errors':errors,'sample':sample,'format':'per-record auto-detection: FortiGate key=value or ECS JSON lines'},indent=2));return 0
        if args.command=='analyze':
            from .pipeline import analyze
            config=resolve_config(args.config,config_overrides(args),args.output)
            if not args.quiet:console.print('Selected resources: '+json.dumps({k:config[k] for k in ['selected_profile','memory_gb','threads','batch_records','spill_gb']}),markup=False)
            def progress(p):
                if not args.quiet:console.print(f"{p['phase']}: {p['processed_bytes']:,}/{p['total_bytes']:,} bytes | {p['records_parsed']:,} parsed | {p['malformed_records']:,} rejected | {p['incidents_found']:,} candidates",markup=False)
            result=analyze(args.input,args.output,args.job_id or args.output.name,config,progress)
            if config['ai_provider']!='none':
                from .ai import review_run
                result['ai_review']=review_run(args.output,config)
            print(json.dumps(result,default=iso));return 0
        if args.command=='incidents':
            import duckdb
            if not 0<=args.offset or not 1<=args.limit<=1000:raise ValueError('Invalid pagination')
            if load_json(args.run/'manifest.v1.json')['incident_count']==0:
                print('[]' if args.json else 'No candidate incidents found.');return 0
            # Scan summaries in DuckDB; do not load the whole JSONL into Python to sort it.
            con=duckdb.connect()
            try:
                con.execute("SET memory_limit='256MB'");con.execute('SET threads=1')
                sort={'id':'incident_id','time':'first_seen,incident_id','severity':"CASE severity WHEN 'high' THEN 0 ELSE 1 END,first_seen,incident_id"}[args.sort]
                cur=con.execute('SELECT * FROM read_json_auto(?) ORDER BY '+sort+' LIMIT ? OFFSET ?',[str(args.run/'incidents.v1.jsonl'),args.limit,args.offset])
                cols=[c[0] for c in cur.description];rows=[dict(zip(cols,r)) for r in cur.fetchall()]
            finally:con.close()
            if args.json:print(json.dumps(rows,default=iso));return 0
            table=Table(title='Candidate investigations — not confirmed attacks')
            for col in ['incident_id','severity','incident_kind','detection_count']:table.add_column(col)
            for r in rows:table.add_row(*(str(r[c]) for c in ['incident_id','severity','incident_kind','detection_count']))
            console.print(table);return 0
        if args.command=='show':
            from .results import get_incident
            b=get_incident(args.run,args.incident)
            if args.json:print(json.dumps(b,indent=2));return 0
            console.print(b['incident_id']+' — '+b['title'],markup=False)
            for s in b['steps']:
                console.print(f"{s['step_index']}. {s['timestamp']} {s['summary']} [{s['technique_id'] or 'unmapped'}]\n   Evidence: {', '.join(s['evidence_ids'][:3])}\n   Limit: {s['uncertainty_reason']}",markup=False)
            console.print('AI: '+b['ai_review']['status'],markup=False)
            if b['ai_review'].get('status')=='completed':
                review=b['ai_review']['result']
                console.print('AI explanation: '+review['explanation'],markup=False)
                console.print('Missing evidence: '+('; '.join(review['missing_evidence']) or 'None reported; analyst verification still required.'),markup=False)
            if b['steps_truncated']:console.print('Preview truncated; full detections are in findings.parquet.',markup=False)
            return 0
        if args.command=='evidence':
            from .results import evidence
            print(json.dumps(evidence(args.run,args.id),default=iso,indent=2));return 0
        if args.command=='validate':
            from .results import validate_run
            print(json.dumps(validate_run(args.run),indent=2));return 0
        if args.command=='review':
            from .ai import review_run
            config=resolve_config(args.config,config_overrides(args),args.run)
            print(json.dumps(review_run(args.run,config,args.incident),indent=2));return 0
    except KeyboardInterrupt:
        console.print('Interrupted. Partial run diagnostics are preserved.',markup=False);return 130
    except Exception as exc:
        console.print('Error: '+str(exc),markup=False);return 1
    return 0
