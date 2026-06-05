import { FormEvent, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type View = 'dashboard' | 'alerts' | 'events' | 'rules' | 'ingest' | 'report';
type FormatType = 'auth_log' | 'nginx_access' | 'json';

type SeverityCount = { severity: Severity; count: number };
type TopIp = { source_ip: string; count: number };
type TopUsername = { username: string; count: number };
type EventOverTime = { time_bucket: string; count: number };

type ParsedEvent = {
  id: number;
  log_id: number;
  timestamp: string;
  event_type: string;
  source_ip: string;
  username?: string | null;
  status_code?: number | null;
  request_path?: string | null;
  user_agent?: string | null;
  raw_message: string;
  country_code?: string | null;
};

type Alert = {
  id: number;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  timestamp: string;
  explanation: string;
  recommended_action: string;
  false_positive_notes: string;
};

type AlertDetail = Alert & { events: ParsedEvent[] };

type Rule = {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  threshold_window_seconds: number;
  threshold_count: number;
  enabled: boolean;
};

type DashboardStats = {
  total_events: number;
  severity_counts: SeverityCount[];
  top_ips: TopIp[];
  top_usernames: TopUsername[];
  events_over_time: EventOverTime[];
  recent_alerts: Alert[];
};

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000/api';
const severityRank: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const severityClass: Record<Severity, string> = {
  CRITICAL: 'border-red-400/70 bg-red-500/15 text-red-100',
  HIGH: 'border-orange-400/70 bg-orange-500/15 text-orange-100',
  MEDIUM: 'border-yellow-400/70 bg-yellow-500/15 text-yellow-100',
  LOW: 'border-sky-400/70 bg-sky-500/15 text-sky-100',
  INFO: 'border-slate-400/70 bg-slate-500/15 text-slate-100',
};

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) return response.json() as Promise<T>;
  return response.text() as Promise<T>;
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString();
}

function Badge({ severity }: { severity: Severity }) {
  return <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${severityClass[severity]}`}>{severity}</span>;
}

function Card({ title, value, hint }: { title: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-5 shadow-xl shadow-black/10">
      <div className="text-sm text-slate-400">{title}</div>
      <div className="mt-2 text-3xl font-bold tracking-tight text-white">{value}</div>
      {hint && <div className="mt-2 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-white/10 bg-white/[0.03] p-8 text-center">
      <div className="text-lg font-semibold text-white">{title}</div>
      <div className="mt-2 text-sm text-slate-400">{body}</div>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<ParsedEvent[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertDetail | null>(null);
  const [status, setStatus] = useState('Ready.');
  const [loading, setLoading] = useState(false);

  const refreshAll = async () => {
    const [nextStats, nextAlerts, nextEvents, nextRules] = await Promise.all([
      api<DashboardStats>('/dashboard/stats'),
      api<Alert[]>('/alerts'),
      api<ParsedEvent[]>('/events'),
      api<Rule[]>('/rules'),
    ]);
    setStats(nextStats);
    setAlerts(nextAlerts.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]));
    setEvents(nextEvents);
    setRules(nextRules);
  };

  useEffect(() => {
    refreshAll().catch((error: Error) => setStatus(`API not reachable yet: ${error.message}`));
  }, []);

  const runAction = async (label: string, action: () => Promise<void>) => {
    try {
      setLoading(true);
      setStatus(`${label}...`);
      await action();
      setStatus(`${label} complete.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const loadDemoLogs = () =>
    runAction('Loading demo logs', async () => {
      await api('/logs/demo', { method: 'POST' });
      await refreshAll();
      setView('dashboard');
    });

  const clearData = () =>
    runAction('Clearing data', async () => {
      await api('/logs/clear', { method: 'DELETE' });
      setSelectedAlert(null);
      await refreshAll();
    });

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,#12335c_0,#08111f_34%,#050914_100%)]">
      <div className="flex min-h-screen">
        <aside className="hidden w-72 shrink-0 border-r border-white/10 bg-black/20 p-6 lg:block">
          <div>
            <div className="text-xs uppercase tracking-[0.3em] text-cyan-300">BlueWatch</div>
            <h1 className="mt-2 text-2xl font-black text-white">Lite SIEM</h1>
            <p className="mt-3 text-sm text-slate-400">Local-only defensive log analysis dashboard.</p>
          </div>
          <nav className="mt-10 space-y-2">
            {(['dashboard', 'alerts', 'events', 'rules', 'ingest', 'report'] as View[]).map((item) => (
              <button
                key={item}
                onClick={() => setView(item)}
                className={`w-full rounded-xl px-4 py-3 text-left text-sm font-semibold capitalize transition ${
                  view === item ? 'bg-cyan-400 text-slate-950' : 'text-slate-300 hover:bg-white/10 hover:text-white'
                }`}
              >
                {item}
              </button>
            ))}
          </nav>
          <div className="mt-8 space-y-3">
            <button disabled={loading} onClick={loadDemoLogs} className="w-full rounded-xl bg-emerald-400 px-4 py-3 text-sm font-bold text-slate-950 hover:bg-emerald-300 disabled:opacity-50">
              Load Demo Logs
            </button>
            <button disabled={loading} onClick={clearData} className="w-full rounded-xl border border-white/10 px-4 py-3 text-sm font-bold text-slate-300 hover:bg-white/10 disabled:opacity-50">
              Clear Data
            </button>
          </div>
        </aside>

        <main className="flex-1 p-5 lg:p-8">
          <div className="mb-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/10 bg-white/[0.04] p-4 md:flex-row md:items-center">
            <div>
              <div className="text-sm text-slate-400">API: {API_BASE}</div>
              <div className="mt-1 text-sm text-cyan-100">{status}</div>
            </div>
            <div className="flex flex-wrap gap-2 lg:hidden">
              {(['dashboard', 'alerts', 'events', 'rules', 'ingest', 'report'] as View[]).map((item) => (
                <button key={item} onClick={() => setView(item)} className={`rounded-lg px-3 py-2 text-xs font-semibold capitalize ${view === item ? 'bg-cyan-400 text-slate-950' : 'bg-white/10 text-slate-200'}`}>
                  {item}
                </button>
              ))}
            </div>
          </div>

          {view === 'dashboard' && <Dashboard stats={stats} alerts={alerts} onSelectAlert={setSelectedAlert} setView={setView} />}
          {view === 'alerts' && <Alerts alerts={alerts} selectedAlert={selectedAlert} onSelectAlert={setSelectedAlert} refreshAll={refreshAll} setStatus={setStatus} />}
          {view === 'events' && <Events initialEvents={events} setStatus={setStatus} />}
          {view === 'rules' && <Rules rules={rules} refreshAll={refreshAll} setStatus={setStatus} />}
          {view === 'ingest' && <Ingest refreshAll={refreshAll} setStatus={setStatus} />}
          {view === 'report' && <Report setStatus={setStatus} />}
        </main>
      </div>
    </div>
  );
}

function Dashboard({ stats, alerts, onSelectAlert, setView }: { stats: DashboardStats | null; alerts: Alert[]; onSelectAlert: (alert: AlertDetail | null) => void; setView: (view: View) => void }) {
  if (!stats) return <EmptyState title="Waiting for API" body="Start the FastAPI backend, then refresh the page." />;
  const criticalHigh = stats.severity_counts.filter((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH').reduce((sum, item) => sum + item.count, 0);
  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-3xl font-black text-white">Dashboard</h2>
        <p className="mt-2 text-slate-400">Security events, rule matches, and defensive triage indicators.</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card title="Total Events" value={stats.total_events} hint="Parsed from local sample logs" />
        <Card title="Alerts" value={alerts.length} hint="Rule-based detections" />
        <Card title="Critical/High" value={criticalHigh} hint="Prioritize these first" />
        <Card title="Rules Enabled" value={stats.recent_alerts.length ? 'Active' : 'Ready'} hint="Manage thresholds in Rules" />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Severity Breakdown">
          <div className="space-y-3">
            {stats.severity_counts.map((item) => (
              <div key={item.severity}>
                <div className="mb-1 flex justify-between text-sm"><span>{item.severity}</span><span>{item.count}</span></div>
                <div className="h-2 rounded-full bg-white/10"><div className="h-2 rounded-full bg-cyan-300" style={{ width: `${Math.min(100, item.count * 12)}%` }} /></div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Top Source IPs">
          {stats.top_ips.length ? stats.top_ips.map((item) => <MiniRow key={item.source_ip} left={item.source_ip} right={`${item.count} events`} />) : <p className="text-sm text-slate-400">No data yet.</p>}
        </Panel>
        <Panel title="Top Usernames">
          {stats.top_usernames.length ? stats.top_usernames.map((item) => <MiniRow key={item.username} left={item.username} right={`${item.count} events`} />) : <p className="text-sm text-slate-400">No usernames yet.</p>}
        </Panel>
      </div>
      <Panel title="Recent Alerts">
        {stats.recent_alerts.length ? (
          <AlertTable alerts={stats.recent_alerts} onOpen={async (alert) => {
            const detail = await api<AlertDetail>(`/alerts/${alert.id}`);
            onSelectAlert(detail);
            setView('alerts');
          }} />
        ) : <EmptyState title="No alerts" body="Load demo logs to trigger every built-in detection." />}
      </Panel>
    </section>
  );
}

function Alerts({ alerts, selectedAlert, onSelectAlert, refreshAll, setStatus }: { alerts: Alert[]; selectedAlert: AlertDetail | null; onSelectAlert: (alert: AlertDetail | null) => void; refreshAll: () => Promise<void>; setStatus: (message: string) => void }) {
  const [severity, setSeverity] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [username, setUsername] = useState('');
  const [filtered, setFiltered] = useState<Alert[]>(alerts);

  useEffect(() => setFiltered(alerts), [alerts]);

  const runFilter = async () => {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (sourceIp) params.set('source_ip', sourceIp);
    if (username) params.set('username', username);
    const result = await api<Alert[]>(`/alerts?${params.toString()}`);
    setFiltered(result);
    setStatus(`Loaded ${result.length} filtered alerts.`);
  };

  return (
    <section className="space-y-6">
      <Header title="Alerts" subtitle="Review rule matches and open alert details for evidence and defensive guidance." />
      <Panel title="Filters">
        <div className="grid gap-3 md:grid-cols-4">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="input"><option value="">Any severity</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s}>{s}</option>)}</select>
          <input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} className="input" placeholder="Source IP" />
          <input value={username} onChange={(e) => setUsername(e.target.value)} className="input" placeholder="Username" />
          <button onClick={runFilter} className="button-primary">Apply Filter</button>
        </div>
      </Panel>
      <div className="grid gap-4 xl:grid-cols-5">
        <div className="xl:col-span-3"><Panel title={`Alert Queue (${filtered.length})`}>{filtered.length ? <AlertTable alerts={filtered} onOpen={async (alert) => onSelectAlert(await api<AlertDetail>(`/alerts/${alert.id}`))} /> : <EmptyState title="No alerts found" body="Try clearing filters or loading demo logs." />}</Panel></div>
        <div className="xl:col-span-2"><AlertDetailPanel alert={selectedAlert} refreshAll={refreshAll} /></div>
      </div>
    </section>
  );
}

function AlertDetailPanel({ alert }: { alert: AlertDetail | null; refreshAll: () => Promise<void> }) {
  if (!alert) return <Panel title="Alert Detail"><p className="text-sm text-slate-400">Select an alert to review matched events and recommended defensive action.</p></Panel>;
  return (
    <Panel title={`Alert #${alert.id}`}>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3"><h3 className="text-xl font-bold text-white">{alert.rule_name}</h3><Badge severity={alert.severity} /></div>
        <Info label="When" value={formatDate(alert.timestamp)} />
        <Info label="Why this alert fired" value={alert.explanation} />
        <Info label="Recommended defensive action" value={alert.recommended_action} />
        <Info label="False positive notes" value={alert.false_positive_notes} />
        <div>
          <div className="mb-2 text-xs uppercase tracking-widest text-slate-500">Matched events</div>
          <div className="max-h-96 space-y-2 overflow-auto code-scroll">
            {alert.events.map((event) => <pre key={event.id} className="whitespace-pre-wrap rounded-xl bg-black/30 p-3 text-xs text-slate-300">{event.raw_message}</pre>)}
          </div>
        </div>
      </div>
    </Panel>
  );
}

function Events({ initialEvents, setStatus }: { initialEvents: ParsedEvent[]; setStatus: (message: string) => void }) {
  const [events, setEvents] = useState(initialEvents);
  const [sourceIp, setSourceIp] = useState('');
  const [username, setUsername] = useState('');
  const [search, setSearch] = useState('');
  useEffect(() => setEvents(initialEvents), [initialEvents]);

  const filterEvents = async () => {
    const params = new URLSearchParams();
    if (sourceIp) params.set('source_ip', sourceIp);
    if (username) params.set('username', username);
    if (search) params.set('search', search);
    const result = await api<ParsedEvent[]>(`/events?${params.toString()}`);
    setEvents(result);
    setStatus(`Loaded ${result.length} events.`);
  };

  return (
    <section className="space-y-6">
      <Header title="Events" subtitle="Search raw parsed events by source IP, username, or message text." />
      <Panel title="Event Search">
        <div className="grid gap-3 md:grid-cols-4"><input className="input" placeholder="Source IP" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} /><input className="input" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} /><input className="input" placeholder="Text search" value={search} onChange={(e) => setSearch(e.target.value)} /><button className="button-primary" onClick={filterEvents}>Search</button></div>
      </Panel>
      <Panel title={`Parsed Events (${events.length})`}>
        <div className="overflow-x-auto"><table className="table"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>User</th><th>Status</th><th>Message</th></tr></thead><tbody>{events.map((event) => <tr key={event.id}><td>{formatDate(event.timestamp)}</td><td>{event.event_type}</td><td>{event.source_ip}</td><td>{event.username ?? '-'}</td><td>{event.status_code ?? '-'}</td><td className="max-w-lg truncate">{event.raw_message}</td></tr>)}</tbody></table></div>
      </Panel>
    </section>
  );
}

function Rules({ rules, refreshAll, setStatus }: { rules: Rule[]; refreshAll: () => Promise<void>; setStatus: (message: string) => void }) {
  const updateRule = async (rule: Rule, patch: Partial<Rule>) => {
    await api<Rule>(`/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify(patch) });
    await refreshAll();
    setStatus(`Updated ${rule.name}.`);
  };
  const resetRules = async () => {
    await api('/rules/reset', { method: 'POST' });
    await refreshAll();
    setStatus('Rules reset to defaults.');
  };
  return (
    <section className="space-y-6">
      <Header title="Rules" subtitle="Enable, disable, and tune local defensive detection thresholds." />
      <div className="flex justify-end"><button className="button-secondary" onClick={resetRules}>Reset Defaults</button></div>
      <div className="grid gap-4 xl:grid-cols-2">
        {rules.map((rule) => <RuleCard key={rule.id} rule={rule} onUpdate={updateRule} />)}
      </div>
    </section>
  );
}

function RuleCard({ rule, onUpdate }: { rule: Rule; onUpdate: (rule: Rule, patch: Partial<Rule>) => Promise<void> }) {
  const [count, setCount] = useState(String(rule.threshold_count));
  const [windowSeconds, setWindowSeconds] = useState(String(rule.threshold_window_seconds));
  useEffect(() => { setCount(String(rule.threshold_count)); setWindowSeconds(String(rule.threshold_window_seconds)); }, [rule.threshold_count, rule.threshold_window_seconds]);
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-5">
      <div className="flex items-start justify-between gap-3"><div><h3 className="font-bold text-white">{rule.name}</h3><p className="mt-2 text-sm text-slate-400">{rule.description}</p></div><Badge severity={rule.severity} /></div>
      <div className="mt-5 grid gap-3 md:grid-cols-3">
        <label className="text-sm text-slate-400">Count<input className="input mt-1" type="number" value={count} onChange={(e) => setCount(e.target.value)} /></label>
        <label className="text-sm text-slate-400">Window seconds<input className="input mt-1" type="number" value={windowSeconds} onChange={(e) => setWindowSeconds(e.target.value)} /></label>
        <div className="flex items-end gap-2"><button className="button-primary flex-1" onClick={() => onUpdate(rule, { threshold_count: Number(count), threshold_window_seconds: Number(windowSeconds) })}>Save</button><button className={rule.enabled ? 'button-danger' : 'button-secondary'} onClick={() => onUpdate(rule, { enabled: !rule.enabled })}>{rule.enabled ? 'Disable' : 'Enable'}</button></div>
      </div>
    </div>
  );
}

function Ingest({ refreshAll, setStatus }: { refreshAll: () => Promise<void>; setStatus: (message: string) => void }) {
  const [formatType, setFormatType] = useState<FormatType>('auth_log');
  const [content, setContent] = useState('');
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!content.trim()) { setStatus('Paste log content first.'); return; }
    await api('/logs/ingest', { method: 'POST', body: JSON.stringify({ content, format_type: formatType }) });
    setContent('');
    await refreshAll();
    setStatus('Log content ingested and analyzed.');
  };
  const placeholder = useMemo(() => ({
    auth_log: 'Jun  5 22:30:01 server sshd[1234]: Failed password for invalid user admin from 192.0.2.10 port 59123 ssh2',
    nginx_access: '203.0.113.30 - - [05/Jun/2026:22:30:00 +0000] "GET /login HTTP/1.1" 401 530 "-" "Mozilla/5.0"',
    json: '[{"timestamp":"2026-06-05T22:30:00Z","source_ip":"192.0.2.100","event_type":"SSH_LOGIN","status_code":0,"message":"Failed SSH login"}]',
  }), []);
  return (
    <section className="space-y-6">
      <Header title="Log Ingestion" subtitle="Paste local sample logs only. The app does not scan networks or collect credentials." />
      <Panel title="Paste Logs">
        <form className="space-y-4" onSubmit={submit}>
          <select className="input max-w-sm" value={formatType} onChange={(e) => setFormatType(e.target.value as FormatType)}><option value="auth_log">Linux auth.log SSH</option><option value="nginx_access">Nginx access log</option><option value="json">Generic JSON</option></select>
          <textarea className="input min-h-72 font-mono text-sm" placeholder={placeholder[formatType]} value={content} onChange={(e) => setContent(e.target.value)} />
          <button className="button-primary" type="submit">Ingest Logs</button>
        </form>
      </Panel>
    </section>
  );
}

function Report({ setStatus }: { setStatus: (message: string) => void }) {
  const [report, setReport] = useState('');
  const generate = async () => {
    const markdown = await api<string>('/report/generate', { headers: { Accept: 'text/markdown' } });
    setReport(markdown);
    setStatus('Report generated.');
  };
  const download = () => {
    const blob = new Blob([report], { type: 'text/markdown' });
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = `bluewatch-report-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(href);
  };
  return (
    <section className="space-y-6">
      <Header title="Report" subtitle="Generate a local Markdown incident summary." />
      <div className="flex gap-3"><button className="button-primary" onClick={generate}>Generate Report</button><button className="button-secondary" onClick={download} disabled={!report}>Download .md</button></div>
      <Panel title="Markdown Preview">{report ? <pre className="max-h-[620px] overflow-auto whitespace-pre-wrap rounded-xl bg-black/30 p-4 text-sm text-slate-200 code-scroll">{report}</pre> : <p className="text-sm text-slate-400">Generate a report after loading logs.</p>}</Panel>
    </section>
  );
}

function AlertTable({ alerts, onOpen }: { alerts: Alert[]; onOpen: (alert: Alert) => void }) {
  return <div className="overflow-x-auto"><table className="table"><thead><tr><th>Severity</th><th>Rule</th><th>Timestamp</th><th>Summary</th><th></th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id}><td><Badge severity={alert.severity} /></td><td>{alert.rule_name}</td><td>{formatDate(alert.timestamp)}</td><td className="max-w-xl truncate">{alert.explanation}</td><td><button className="text-cyan-300 hover:text-cyan-100" onClick={() => onOpen(alert)}>Open</button></td></tr>)}</tbody></table></div>;
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-5 shadow-xl shadow-black/10"><h3 className="mb-4 text-lg font-bold text-white">{title}</h3>{children}</div>;
}

function Header({ title, subtitle }: { title: string; subtitle: string }) {
  return <div><h2 className="text-3xl font-black text-white">{title}</h2><p className="mt-2 text-slate-400">{subtitle}</p></div>;
}

function MiniRow({ left, right }: { left: string; right: string }) {
  return <div className="flex justify-between border-b border-white/10 py-2 text-sm last:border-b-0"><span className="font-mono text-slate-200">{left}</span><span className="text-slate-400">{right}</span></div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div><div className="mb-1 text-xs uppercase tracking-widest text-slate-500">{label}</div><p className="text-sm leading-6 text-slate-200">{value}</p></div>;
}
