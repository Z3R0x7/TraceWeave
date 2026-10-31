#!/usr/bin/env python3
"""Team-authored connected fixture, NOT organizer ground truth."""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
def base(eid,time,category,action):
    return {'@timestamp':time,'event':{'id':eid,'category':[category],'action':action},
            'host':{'name':'LAB-A','ip':['10.0.0.10']},'user':{'name':'testuser','domain':'LAB'}}
process=base('scenario-process','2026-10-31T10:00:00Z','process','process_created')
process['process']={'name':'powershell.exe','entity_id':'scenario-process-1','parent':{'name':'winword.exe'}}
registry=base('scenario-registry','2026-10-31T10:01:00Z','registry','registry_value_set')
registry['process']={'name':'powershell.exe','entity_id':'scenario-process-1'}
registry['registry']={'path':r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo'}
network=base('scenario-network','2026-10-31T10:02:00Z','network','network_connection')
network['process']={'name':'powershell.exe','entity_id':'scenario-process-1'}
network['source']={'ip':'10.0.0.10'};network['destination']={'ip':'198.51.100.23','port':443};network['network']={'bytes':2048}
for name,events in [('a.log',[network]),('z.log',[process,registry])]:
    with (a.output/name).open('w') as f:
        for e in events:f.write(json.dumps(e)+'\n')
print('Created explicitly connected, out-of-file-order team fixture. Enable --demo-indicators for its test IP.')
