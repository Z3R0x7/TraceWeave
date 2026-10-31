#!/usr/bin/env python3
"""Convert downloaded text/CSV indicators or ATT&CK STIX into offline engine snapshots."""
import argparse,csv,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from killchain.common import atomic_json
from killchain.enrichment import load_indicators,load_playbooks


def active(obj):return not obj.get('revoked') and not obj.get('x_mitre_deprecated')


def stix_playbooks(bundle,source,retrieved_at):
    objects={item['id']:item for item in bundle.get('objects',[]) if 'id' in item and active(item)}
    def external_id(obj):
        return next((ref.get('external_id') for ref in obj.get('external_references',[]) if ref.get('source_name')=='mitre-attack' and ref.get('external_id')),None)
    techniques={}
    for relationship in objects.values():
        if relationship.get('type')!='relationship' or relationship.get('relationship_type')!='mitigates':continue
        mitigation=objects.get(relationship.get('source_ref'),{});technique=objects.get(relationship.get('target_ref'),{})
        tid=external_id(technique);mid=external_id(mitigation)
        if mitigation.get('type')!='course-of-action' or technique.get('type')!='attack-pattern' or not tid or not mid:continue
        card={'id':mid,'name':mitigation.get('name',mid),'description':mitigation.get('description','Review the cited mitigation.'),
              'url':next((r['url'] for r in mitigation.get('external_references',[]) if r.get('source_name')=='mitre-attack' and r.get('url')),'')}
        techniques.setdefault(tid,[]).append(card)
    return {'source':source,'retrieved_at':retrieved_at,'techniques':techniques}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind',choices=['ip','domain','attack-stix'])
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source',required=True);parser.add_argument('--retrieved-at',required=True)
    parser.add_argument('--csv-column',help='For CSV feeds, column containing the IP/domain')
    args=parser.parse_args()
    if args.output.exists():parser.error('Choose a new snapshot output path')
    if args.input.stat().st_size>128*2**20:parser.error('Snapshot preparation input exceeds 128 MiB; prefilter it first')
    if args.kind=='attack-stix':
        with args.input.open() as handle:data=stix_playbooks(json.load(handle),args.source,args.retrieved_at)
    else:
        indicators=[]
        with args.input.open() as handle:
            if args.csv_column:
                for row in csv.DictReader(line for line in handle if not line.lstrip().startswith('#')):
                    if row.get(args.csv_column):indicators.append({'type':args.kind,'value':row[args.csv_column].strip()})
            else:
                for line in handle:
                    value=line.strip()
                    if value and not value.startswith('#'):indicators.append({'type':args.kind,'value':value})
        data={'source':args.source,'retrieved_at':args.retrieved_at,'indicators':indicators}
    atomic_json(args.output,data)
    try:(load_playbooks if args.kind=='attack-stix' else load_indicators)(args.output)
    except ValueError:
        args.output.unlink();raise
    print(json.dumps({'snapshot':str(args.output),'source':args.source,'entries':len(data.get('indicators',data.get('techniques',{})))}))


if __name__=='__main__':main()
