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
        supplied = json.loads(Path(config_path).read_text())
        unknown = set(supplied) - set(config)
        if unknown: raise ValueError('Unknown configuration keys: ' + ', '.join(sorted(unknown)))
        config.update(supplied)
    config.update({k:v for k,v in (overrides or {}).items() if v is not None})
    profile = config['profile']
    if profile not in {'auto', 'conservative', 'balanced', 'throughput'}: raise ValueError('Unknown profile')
    hw = hardware(workspace)
    if hw['memory_available_gb'] < 1: raise ValueError('At least 1 GiB available memory is required')
    selected = ('conservative' if hw['memory_available_gb'] < 8 else 'balanced') if profile == 'auto' else profile
    fraction, max_threads = {'conservative':(.25, 2), 'balanced':(.35, 4), 'throughput':(.40, 8)}[selected]
    budget = round(min(4., hw['memory_available_gb'] * fraction), 2)
    if config['memory_gb'] is None: config['memory_gb'] = max(.25, budget)
    if config['threads'] is None: config['threads'] = min(hw['cpu_cores'], max_threads)
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
