"""Resource sizing and bounded-run telemetry; no third-party dependencies."""
import os
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

GB = 1_000_000_000


def memory_available():
    if sys.platform.startswith('linux'):
        info = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(info['MemAvailable'].split()[0]) * 1024
        try:
            group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
            folder = Path('/sys/fs/cgroup') / group.lstrip('/')
            # Parent limits also constrain a nested service.
            while folder.is_relative_to('/sys/fs/cgroup'):
                limit = (folder / 'memory.max').read_text().strip()
                if limit != 'max':
                    available = min(available, max(0, int(limit) - int((folder / 'memory.current').read_text())))
                if folder == Path('/sys/fs/cgroup'):
                    break
                folder = folder.parent
        except (OSError, StopIteration, ValueError):
            pass
        return available
    if sys.platform == 'darwin':
        output = subprocess.run(['vm_stat'], capture_output=True, text=True, check=True, timeout=3).stdout
        import re
        page = int(re.search(r'page size of (\d+) bytes', output).group(1))
        pages = dict((k.strip(), int(v.strip().strip('.'))) for k, v in (line.split(':') for line in output.splitlines()[1:] if ':' in line))
        return page * sum(pages.get(k, 0) for k in ('Pages free', 'Pages inactive', 'Pages speculative'))
    raise ValueError('Automatic memory sizing supports Linux and macOS')


def resource_budget():
    available = memory_available()
    budget = min(8 * GB, int(max(0, available - 2 * GB) * 0.60))
    requested = os.environ.get('TRACEWEAVE_MEMORY_GB')
    if requested:
        value = float(requested)
        if not 1 <= value <= 8:
            raise ValueError('TRACEWEAVE_MEMORY_GB must be between 1 and 8')
        budget = min(budget, int(value * GB))
    if budget < GB:
        raise ValueError('Insufficient available memory; need a safe analysis budget of at least 1 GB')
    return dict(memory_bytes=budget, available_bytes_at_start=available,
                sqlite_cache_bytes=min(2 * GB, budget // 4),
                node_heap_bytes=min(512 * 1024**2, budget // 5),
                batch_bytes=min(8 * 1024**2, budget // 128))


class ResourceMonitor:
    def __init__(self, budget, output):
        self.budget = budget
        self.output = Path(output)
        self.child_pid = None
        self.peak = 0
        self.last = 0
        self.observed = {}

    def sample(self):
        if self.observed and time.monotonic() - self.last < 1:
            return self.observed
        self.last = time.monotonic()
        if sys.platform.startswith('linux'):
            total = 0
            pending = [os.getpid()]
            seen = set()
            while pending:
                pid = pending.pop()
                if pid in seen:
                    continue
                seen.add(pid)
                try:
                    total += int(Path(f'/proc/{pid}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
                    pending.extend(int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split())
                except (OSError, ValueError, IndexError):
                    pass
            measurement = 'simultaneous process tree RSS; shared pages may be counted more than once'
        else:
            total = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss + resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            measurement = 'lifetime RSS upper bound; live child RSS unavailable until child exits'
        self.peak = max(self.peak, total)
        free = shutil.disk_usage(self.output).free
        self.observed = dict(process_tree_peak_bytes=self.peak, memory_measurement=measurement, free_disk_bytes=free)
        if total > self.budget['memory_bytes']:
            raise RuntimeError('Analysis exceeded its memory budget; partial artifacts retained')
        if free < 512 * 1024**2:
            raise RuntimeError('Analysis stopped before disk exhaustion; partial artifacts retained')
        return self.observed
