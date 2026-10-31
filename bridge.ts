import {createInterface} from 'node:readline';
import {normalize, newStats} from './vendor/jevline/engine/src/normalize.ts';
import {resolveProcesses} from './vendor/jevline/engine/src/identity.ts';
import {buildLinks, pathKey, launchedPaths, PERSISTENCE_KEY} from './vendor/jevline/engine/src/links.ts';
// One bounded request at a time; the Python coordinator persists every result before continuing.
for await (const line of createInterface({input: process.stdin})) {
  const rows = JSON.parse(line), stats = newStats();
  const rawById = new Map(rows.map(r=>[r.id,r.raw]));
  const events = [], origins = [];
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const e = normalize({nested:r.raw._canonical ?? r.raw, id:String(r.id), line:r.line}, r.file, events.length, stats);
    if (e) {
      const raw=r.raw._canonical ?? r.raw;
      const fullHost=raw['host.name'] ?? raw.host?.name ?? raw.Computer ?? raw.ComputerName ?? raw.hostname;
      if (typeof fullHost==='string') e.host=fullHost.trim().toLowerCase();
      let user=raw['user.name'] ?? raw.user?.name ?? (e.kind==='logon'||e.kind==='logon_failed' ? raw.TargetUserName ?? raw.winlog?.event_data?.TargetUserName : raw.SubjectUserName ?? raw.winlog?.event_data?.SubjectUserName);
      const auth=e.kind==='logon'||e.kind==='logon_failed';
      const domain=raw['user.domain'] ?? raw.user?.domain ?? (auth ? raw.TargetDomainName ?? raw.winlog?.event_data?.TargetDomainName : raw.SubjectDomainName ?? raw.winlog?.event_data?.SubjectDomainName);
      if (typeof user==='string' && user && user!=='-') {
        if (domain && !user.includes('\\') && !user.includes('@')) user=domain+'\\'+user;
        user=user.toLowerCase();
        if (e.kind==='logon'||e.kind==='logon_failed') e.account=user;
        if (e.proc.user) e.proc.user=user;
      }
      const rawTime=raw['@timestamp'] ?? raw.timestamp ?? raw.TimeCreated;
      if (typeof rawTime==='string' && /^\d{4}-\d{2}-\d{2}[T ]/.test(rawTime) && !/(Z|[+-]\d{2}:?\d{2})$/i.test(rawTime) && !raw.UtcTime && !raw.winlog?.event_data?.UtcTime) {
        if (e.t!==null) stats.untimed++;
        e.t=null;
      }
      e.global_paths={
        file:e.file_path ? pathKey(e.file_path) : undefined,
        image:e.proc.path ? pathKey(e.proc.path) : undefined,
        persistence:e.kind==='registry_set' && e.reg?.key && PERSISTENCE_KEY.test(e.reg.key) ? launchedPaths(e.reg.value) : (e.kind==='service_install'||e.kind==='task_create' ? launchedPaths(e.launches) : [])
      };
      events.push(e); origins.push(r.id);
    }
  }
  const processes = resolveProcesses(events), graph = buildLinks(events, processes);
  // PID-only and name-only identities are scoped to this request, never merged across batches.
  const key = (k) => k.startsWith('g:') || !processes.nodes.has(k) || processes.nodes.get(k).type !== 'process' ? k : `batch:${rows[0].id}:${k}`;
  const nodes = [...processes.nodes.values()].map(n => ({...n, key:key(n.key), events:n.events.map(i=>origins[i]), starts:n.starts.map(i=>origins[i])}));
  const links = graph.links.map(l=>({...l, upstream_type:l.type, type:l.evidence.length && l.evidence.every(i=>rawById.get(origins[i])?._canonical) ? 'observed_firewall_relation' : l.type, from:key(l.from), to:key(l.to), evidence:l.evidence.map(i=>origins[i])}));
  process.stdout.write(JSON.stringify({events:events.map((e,i)=>({...e, evidence_id:origins[i], actor:key(processes.actor[i] || '')})),nodes,links,stats:{...stats,bySource:Object.fromEntries(stats.bySource)}})+'\n');
}
