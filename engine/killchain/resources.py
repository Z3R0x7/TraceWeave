from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import psutil

DEFAULTS = Path(__file__).resolve().parents[1] / 'defaults.json'

def _read(path):
    try: return Path(path).read_text().strip()
    except OSError: return None

def hardware(workspace):
    ram = psutil.virtual_memory()
    total, available = ram.total, ram.available
    limits = []
    for p in ['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes']:
        v = _read(p)
        if v and v.isdigit() and 0 < int(v) < 2**60:
            limits.append(int(v))
    if limits:
        total = min(total, *limits)
        used = _read('/sys/fs/cgroup/memory.current') or _read('/sys/fs/cgroup/memory/memory.usage_in_bytes')
        available = min(available, max(0, total - int(used))) if used and used.isdigit() else min(available, total)
    affinity = len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else (os.cpu_count() or 1)
    cores = max(1, min(os.cpu_count() or 1, affinity))
    quota = _read('/sys/fs/cgroup/cpu.max')
    if quota and quota.split()[0] != 'max':
        q, period = map(int, quota.split())
        cores = min(cores, max(1, q // period))
    else:
        q, period = _read('/sys/fs/cgroup/cpu/cpu.cfs_quota_us'), _read('/sys/fs/cgroup/cpu/cpu.cfs_period_us')
        if q and period and int(q) > 0: cores = min(cores, max(1, int(q) // int(period)))
    p = Path(workspace).resolve()
    while not p.exists(): p = p.parent
    return {'cpu_cores': cores, 'memory_total_gb': round(total/2**30, 2),
            'memory_available_gb': round(available/2**30, 2),
            'disk_free_gb': round(shutil.disk_usage(p).free/2**30, 2)}

def resolve_config(config_path=None, overrides=None, workspace='.'):
    config = json.loads(DEFAULTS.read_text())
    if config_path:
        if Path(config_path).stat().st_size>2*2**20:raise ValueError('Configuration exceeds 2 MiB; keep inventory/feed snapshots separate')
        supplied = json.loads(Path(config_path).read_text())
        unknown = set(supplied) - set(config)
        if unknown: raise ValueError('Unknown configuration keys: ' + ', '.join(sorted(unknown)))
        config.update(supplied)
    config.update({k:v for k,v in (overrides or {}).items() if v is not None})
    if config['input_format'] not in {'auto','jsonl','fortigate'}: raise ValueError('Unsupported input_format')
    for flag in ['recover_valid_prefix','preflight_audit']:
        if not isinstance(config[flag],bool):raise ValueError(flag+' must be boolean')
    if not isinstance(config['fail_on_binary'],bool): raise ValueError('fail_on_binary must be boolean')
    for key in ['asset_map','allowlist']:
        if not isinstance(config[key],list):raise ValueError(key+' must be a list')
    seen_hosts=set();seen_aliases=set();seen_ips=set()
    for asset in config['asset_map']:
        if not isinstance(asset,dict) or set(asset)-{'host','aliases','ips','criticality'} or not isinstance(asset.get('host'),str):raise ValueError('Asset requires host, optional aliases, ips and criticality')
        if not isinstance(asset.get('criticality',0),(int,float)) or not 0<=asset.get('criticality',0)<=100:raise ValueError('Asset criticality must be 0..100')
        for field,seen in [('aliases',seen_aliases),('ips',seen_ips)]:
            values=asset.get(field,[])
            if not isinstance(values,list) or any(not isinstance(v,str) or not v for v in values):raise ValueError('Asset '+field+' must contain nonempty strings')
            for value in values:
                if value.casefold() in seen:raise ValueError('Ambiguous asset '+field+': '+value)
                seen.add(value.casefold())
        if asset['host'].casefold() in seen_hosts:raise ValueError('Duplicate asset host')
        seen_hosts.add(asset['host'].casefold())
    resolved_aliases={}
    for asset in config['asset_map']:
        for value in [asset['host'],*asset.get('aliases',[])]:
            alias=value.casefold()
            if alias in resolved_aliases and resolved_aliases[alias]!=asset['host']:raise ValueError('Ambiguous host alias: '+value)
            resolved_aliases[alias]=asset['host']
    allowlist_keys=set()
    for item in config['allowlist']:
        if not isinstance(item,dict) or set(item)!={'field','value','reason'} or item['field'] not in {'host_name','account_id','source_ip','destination_ip','process_name'} or any(not isinstance(item[k],str) or not item[k] for k in ['value','reason']):raise ValueError('Allowlist entries require supported field, value and reason')
        key=(item['field'],item['value'])
        if key in allowlist_keys:raise ValueError('Duplicate allowlist field/value')
        allowlist_keys.add(key)
    for key in ['indicator_snapshot','playbook_snapshot']:
        if config[key] is not None:
            path=Path(config[key]).expanduser().resolve()
            if not path.is_file() or path.stat().st_size>64*2**20:raise ValueError(key+' must be a local JSON snapshot under 64 MiB')
            config[key]=str(path)
    from .enrichment import load_indicators,load_playbooks
    load_indicators(config['indicator_snapshot']);load_playbooks(config['playbook_snapshot'])
    profile = config['profile']
    if profile not in {'auto', 'conservative', 'balanced', 'throughput'}: raise ValueError('Unknown profile')
    hw = hardware(workspace)
    if hw['memory_available_gb'] < 1: raise ValueError('At least 1 GiB available memory is required')
    selected = ('conservative' if hw['memory_available_gb'] < 8 else 'balanced') if profile == 'auto' else profile
    fraction, max_threads = {'conservative':(.25, 2), 'balanced':(.35, 4), 'throughput':(.40, 8)}[selected]
    requested_memory=config['memory_gb']
    budget = round(min(4., hw['memory_available_gb'] * fraction), 2)
    if config['memory_gb'] is None: config['memory_gb'] = max(.25, budget)
    if config['threads'] is None: config['threads'] = min(hw['cpu_cores'], max_threads)
    if config['total_memory_gb'] is None:config['total_memory_gb']=round(min(7.,hw['memory_available_gb']*.65),2)
    if not isinstance(config['total_memory_gb'],(int,float)) or not .5<=config['total_memory_gb']<=hw['memory_available_gb']*.8:raise ValueError('Total memory budget must be at least 0.5 GiB and at most 80% of available memory')
    if config['memory_gb']>config['total_memory_gb']*.75:
        if requested_memory is not None:raise ValueError('Database memory budget must leave at least 25% of total memory budget for runtime overhead')
        config['memory_gb']=round(config['total_memory_gb']*.6,2)
    worker_limit=max(1,min(hw['cpu_cores'],8,int(max(.4,config['total_memory_gb']-config['memory_gb']-.4)/.4)))
    if config['parse_workers'] is None:config['parse_workers']=min(worker_limit,4)
    if not isinstance(config['parse_workers'],int) or isinstance(config['parse_workers'],bool) or not 1<=config['parse_workers']<=worker_limit:raise ValueError('parse_workers exceeds CPU/memory budget; maximum '+str(worker_limit))
    if not isinstance(config['timeout_seconds'],(int,float)) or config['timeout_seconds']<0:raise ValueError('timeout_seconds must be nonnegative')
    for key in ['chunk_mb','disk_estimate_multiplier','repeat_window_minutes']:
        if not isinstance(config[key],(int,float)) or isinstance(config[key],bool) or config[key]<=0:raise ValueError(key+' must be positive')
    if int(config['chunk_mb']*2**20)<1 or int(config['max_record_mb']*2**20)<1:raise ValueError('Partition and record byte limits must be at least one byte')
    if not 1<=config['threads']<=hw['cpu_cores']:raise ValueError('threads must be within available CPU cores')
    if config['spill_gb'] is None: config['spill_gb'] = max(1., round((hw['disk_free_gb']-config['min_free_gb']) * .5, 1))
    for key in ['memory_gb','batch_records','batch_bytes_mb','max_record_mb','threads','failure_threshold',
                'failure_window_minutes','reported_rename_threshold','max_incident_steps','spill_gb',
                'ai_max_input_chars','ai_max_output_tokens','ai_timeout_seconds']:
        if not isinstance(config[key], (int,float)) or isinstance(config[key],bool) or config[key] <= 0:
            raise ValueError(key + ' must be a positive number')
    for key in ['threads','batch_records','failure_threshold','failure_window_minutes','max_incident_steps',
                'ai_max_reviews','ai_max_input_chars','ai_max_output_tokens']:
        if not isinstance(config[key],int) or isinstance(config[key],bool): raise ValueError(key+' must be an integer')
    if config['ai_max_reviews'] < 0: raise ValueError('ai_max_reviews must be nonnegative')
    if config['min_free_gb'] < 0: raise ValueError('min_free_gb must be nonnegative')
    if config['memory_gb'] > hw['memory_available_gb'] * .7:
        raise ValueError('Database budget exceeds 70% of available memory; leave headroom or choose another machine')
    if config['ai_provider'] not in {'none','groq','openai'}: raise ValueError('Unsupported AI provider')
    for key in ['indicator_ips','indicator_domains']:
        if not isinstance(config[key],list) or not all(isinstance(x,str) for x in config[key]): raise ValueError(key+' must be a string list')
    if not isinstance(config['demo_indicators'],bool): raise ValueError('demo_indicators must be boolean')
    config['selected_profile'] = selected
    config['hardware'] = hw
    return config
