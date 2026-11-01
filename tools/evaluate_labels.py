#!/usr/bin/env python3
"""Evaluate analyst/ground-truth labels; no inferred false-alarm claim from AI votes."""
import argparse
import json
import math
from pathlib import Path
import sqlite3


def calculate(true_positive,false_positive,unknown=0):
    n=true_positive+false_positive
    if not n:return dict(status='unverified',reviewed=0,unknown=unknown,false_alarm_share=None,target=.30,sample_target_met=False)
    p=false_positive/n;z=1.96
    upper=(p+z*z/(2*n)+z*math.sqrt(p*(1-p)/n+z*z/(4*n*n)))/(1+z*z/n)
    return dict(status='labelled_sample',reviewed=n,unknown=unknown,true_positive=true_positive,false_positive=false_positive,false_alarm_share=p,wilson_95_upper=upper,target=.30,sample_target_met=n>=100 and upper<.30,scope='Supplied labels of emitted candidates only; not recall or whole-dataset accuracy')


def evaluate(database,labels):
    counts=dict(true_positive=0,false_positive=0,unknown=0);seen=set()
    with sqlite3.connect('file:'+str(Path(database).resolve())+'?mode=ro',uri=True) as db:
        with Path(labels).open() as stream:
            while line:=stream.readline(65537):
                if len(line)>65536:raise ValueError('Label record exceeds 64 KiB')
                if not line.strip():continue
                row=json.loads(line);identifier=row.get('incident_id');verdict=row.get('verdict')
                if verdict not in counts or not isinstance(identifier,str) or identifier in seen:raise ValueError('Invalid or duplicate label')
                if not db.execute('SELECT 1 FROM memberships WHERE incident_id=? LIMIT 1',(identifier,)).fetchone():raise ValueError('Label does not reference an emitted baseline candidate')
                if not isinstance(row.get('provenance'),str) or not row['provenance'].strip():raise ValueError('Every label requires its independent review/ground-truth provenance')
                seen.add(identifier);counts[verdict]+=1
    return calculate(**counts)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--database',required=True);parser.add_argument('--labels',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    report=evaluate(args.database,args.labels);Path(args.output).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
