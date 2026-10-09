import CountUp from './CountUp'
import Login from './Login'
import ChatBot from './ChatBot'
import { useState, useEffect, useRef } from 'react'
import {
  Shield, Activity, AlertTriangle, Bug, Users, FileText, LogOut,
  Repeat, ChevronRight, ChevronLeft, X, Search, ExternalLink, TrendingUp, RefreshCw,
  Network, Map,
  BrainCircuit, RadioTower, Sparkles,
} from 'lucide-react'
import {
  getStats, getHealth, getAutomation, setAutomation, getIOCs, getRecurring, getIOCDetail,
  getCVEs, getAPT, getAPTDetail, getArticles, getIOCTypeChart, getSeverityChart, getCVEDetail,
  getCorrelationSummary, getCorrelationClusters, getMalwareCorrelation, getAttackOverview,
  investigateEntity, getSIEMOverview,
} from './api'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer,
} from 'recharts'

const CHART_COLORS = ['#2563eb', '#7c3aed', '#0891b2', '#ca8a04', '#dc2626', '#16a34a', '#ea580c', '#db2777']

function severityBadge(sev) {
  const map = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' }
  return map[sev] || 'badge-gray'
}

export default function App() {
  const [authed] = useState(!!localStorage.getItem('ti_token'))
  const [page, setPage] = useState('overview')
  const [detail, setDetail] = useState(null)   // IOC detail panel
  const [aptDetail, setAptDetail] = useState(null)
  const [cveDetail, setCveDetail] = useState(null)
  const [correlationDetail, setCorrelationDetail] = useState(null)
  const [iocFilter, setIocFilter] = useState({})  // drill-down filter for IOC page

  if (!authed) return <Login />

  const nav = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'iocs', label: 'IOCs', icon: Shield },
    { id: 'cves', label: 'CVEs', icon: Bug },
    { id: 'apt', label: 'APT Groups', icon: Users },
    { id: 'correlations', label: 'Correlations', icon: Network },
    { id: 'attack', label: 'MITRE ATT&CK', icon: Map },
    { id: 'investigate', label: 'AI Investigation', icon: BrainCircuit },
    { id: 'siem', label: 'SIEM Matches', icon: RadioTower },
    { id: 'articles', label: 'Threat Feed', icon: FileText },
  ]

  // helper: jump to IOC page with a filter applied (drill-down from cards)
  function logout() {
    localStorage.removeItem('ti_token')
    window.location.reload()
  }

  function drillToIOCs(filter) {
    setIocFilter(filter)
    setPage('iocs')
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Shield size={22} color="#2563eb" />
          ThreatIntel
        </div>
        {nav.map(n => {
          const Icon = n.icon
          return (
            <div key={n.id}
              className={`nav-item ${page === n.id ? 'active' : ''}`}
              onClick={() => setPage(n.id)}>
              <Icon size={18} />
              {n.label}
            </div>
          )
        })}
        <div className="nav-item" onClick={logout}
          style={{ marginTop: 'auto', color: '#dc2626' }}>
          <LogOut size={18} />
          Logout
        </div>
      </aside>

      <main className="main">
        {page === 'overview' && <Overview drillToIOCs={drillToIOCs} setDetail={setDetail} setPage={setPage} />}
        {page === 'iocs' && <IOCsPage filter={iocFilter} setFilter={setIocFilter} setDetail={setDetail} />}
        {page === 'cves' && <CVEsPage setCveDetail={setCveDetail} />}
        {page === 'apt' && <APTPage setAptDetail={setAptDetail} />}
        {page === 'correlations' && <CorrelationsPage setCorrelationDetail={setCorrelationDetail} />}
        {page === 'attack' && <AttackPage setAptDetail={setAptDetail} />}
        {page === 'investigate' && <InvestigationPage />}
        {page === 'siem' && <SIEMPage setDetail={setDetail} setCveDetail={setCveDetail} />}
        {page === 'articles' && <ArticlesPage />}
      </main>

      {detail && <DetailPanel value={detail} onClose={() => setDetail(null)} />}
      {aptDetail && <APTDetailPanel name={aptDetail} onClose={() => setAptDetail(null)} />}
      {cveDetail && <CVEDetailPanel cve={cveDetail} onClose={() => setCveDetail(null)} />}
      {correlationDetail && <CorrelationDetailPanel name={correlationDetail} onClose={() => setCorrelationDetail(null)} />}
      <ChatBot />
    </div>
  )
}


function ErrorBanner({ message, onRetry }) {
  if (!message) return null
  return (
    <div className="error-banner">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><AlertTriangle size={18} /> {message}</div>
      {onRetry && <button className="retry-btn" onClick={onRetry}><RefreshCw size={14} style={{ marginRight: 4, verticalAlign: 'text-bottom' }} /> Retry</button>}
    </div>
  )
}

/* ---------------- OVERVIEW ---------------- */
function Overview({ drillToIOCs, setDetail, setPage }) {
  const [stats, setStats] = useState(null)
  const [iocTypes, setIocTypes] = useState([])
  const [severity, setSeverity] = useState([])
  const [recurring, setRecurring] = useState([])
  const [health, setHealth] = useState(null)
  const [automation, setAutomationState] = useState(null)
  const [automationBusy, setAutomationBusy] = useState(false)

  useEffect(() => {
    const load = () => {
      getStats().then(setStats)
      getIOCTypeChart().then(setIocTypes)
      getSeverityChart().then(setSeverity)
      getRecurring().then(setRecurring)
      getHealth().then(setHealth)
      getAutomation().then(setAutomationState)
    }
    load()
    const interval = setInterval(load, 60_000)
    return () => clearInterval(interval)
  }, [])

  if (!stats) return <div className="loading">Loading dashboard…</div>

  const toggleAutomation = async () => {
    if (!automation || automationBusy) return
    setAutomationBusy(true)
    try {
      const next = await setAutomation(!automation.enabled)
      setAutomationState(prev => ({ ...prev, ...next }))
      setHealth(prev => prev ? ({ ...prev, auto_refresh_enabled: next.enabled }) : prev)
    } finally { setAutomationBusy(false) }
  }

  const cards = [
    { label: 'Total IOCs', value: stats.total_iocs, icon: Shield, color: '#2563eb', bg: '#eff4ff', onClick: () => drillToIOCs({}) },
    { label: 'Active IOCs', value: stats.active_iocs, icon: Activity, color: '#16a34a', bg: '#f0fdf4', onClick: () => drillToIOCs({ active_only: true }) },
    { label: 'Recurring', value: stats.recurring_iocs, icon: Repeat, color: '#ea580c', bg: '#fff7ed', onClick: () => drillToIOCs({}) },
    { label: 'Critical CVEs', value: stats.critical_cves, icon: AlertTriangle, color: '#dc2626', bg: '#fef2f2', onClick: () => setPage('cves') },
    { label: 'Total CVEs', value: stats.total_cves, icon: Bug, color: '#7c3aed', bg: '#f5f3ff', onClick: () => setPage('cves') },
    { label: 'APT Groups', value: stats.apt_groups, icon: Users, color: '#0891b2', bg: '#ecfeff', onClick: () => setPage('apt') },
  ]

  return (
    <>
      <div className="page-title">Threat Intelligence Overview</div>
      <div className="page-sub">Polled intelligence view · dashboard health refreshes every minute</div>

      {health && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
            <div className="section-title"><RefreshCw size={16} color="#2563eb" /> Data freshness & coverage</div>
            {automation && <button className="page-btn" disabled={automationBusy} onClick={toggleAutomation} style={{ color: automation.enabled ? '#b42318' : '#067647' }}>
              <RefreshCw size={14} /> {automation.enabled ? 'Pause auto refresh' : 'Resume auto refresh'}
            </button>}
          </div>
          <div style={{ color: '#6b7688', fontSize: 13, marginBottom: 14 }}>
            Last data received: {health.last_data_update ? new Date(health.last_data_update).toLocaleString() : 'No data yet'}
            {health.latest_run?.completed_at && ` · Last scheduled refresh: ${new Date(health.latest_run.completed_at).toLocaleString()}`}
            {automation && ` · Auto refresh is ${automation.enabled ? 'enabled' : 'paused'}`}
          </div>
          <div className="grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 16 }}>
            {[
              ['VirusTotal IOCs', health.coverage.vt_iocs], ['GreyNoise IPs', health.coverage.greynoise_ips],
              ['NVD-enriched CVEs', health.coverage.nvd_cves], ['ATT&CK mappings', health.coverage.attack_mappings],
            ].map(([label, value]) => <div key={label} style={{ padding: 12, borderRadius: 8, background: '#f8fafc' }}><div style={{ fontWeight: 700, fontSize: 20, color: '#2563eb' }}>{Number(value).toLocaleString()}</div><div className="stat-label">{label}</div></div>)}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {health.sources.map(s => <span key={s.source} className={`badge ${s.status === 'healthy' ? 'badge-low' : s.status === 'stale' ? 'badge-medium' : 'badge-gray'}`} title={s.last_updated || 'No timestamp'}>{s.source}: {s.status} · {s.item_count.toLocaleString()}</span>)}
          </div>
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 24 }}>
        {cards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className="stat-card" style={{ cursor: "pointer", "--accent": c.color }} onClick={c.onClick}>
              <div className="stat-icon" style={{ background: c.bg }}>
                <Icon size={20} color={c.color} />
              </div>
              <div className="stat-value" style={{ color: c.color }}><CountUp end={c.value} /></div>
              <div className="stat-label">{c.label} <ChevronRight size={12} style={{ verticalAlign: 'middle' }} /></div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-2" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="section-title">IOC Types</div>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={iocTypes} dataKey="value" nameKey="name" cx="50%" cy="50%"
                innerRadius={55} outerRadius={90} paddingAngle={2}>
                {iocTypes.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
            {iocTypes.map((t, i) => (
              <span key={t.name} className="badge badge-gray" style={{ cursor: 'pointer' }}
                onClick={() => drillToIOCs({ ioc_type: t.name })}>
                <span style={{ width: 8, height: 8, borderRadius: 4, background: CHART_COLORS[i % CHART_COLORS.length], display: 'inline-block' }} />
                {t.name} · {t.value}
              </span>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="section-title">CVE Severity</div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={severity}>
              <XAxis dataKey="name" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {severity.map((s, i) => {
                  const col = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#ca8a04', LOW: '#16a34a' }
                  return <Cell key={i} fill={col[s.name] || '#2563eb'} />
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="section-title"><AlertTriangle size={16} color="#dc2626" /> Risk Breakdown</div>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
          {[
            { label: 'HIGH', value: stats.risk_high || 0, color: '#dc2626', bg: '#fef2f2' },
            { label: 'MEDIUM', value: stats.risk_medium || 0, color: '#ea580c', bg: '#fff7ed' },
            { label: 'LOW', value: stats.risk_low || 0, color: '#16a34a', bg: '#f0fdf4' },
          ].map(r => (
            <div key={r.label} onClick={() => drillToIOCs({ risk: r.label })}
              style={{ cursor: 'pointer', padding: 16, borderRadius: 10, background: r.bg, textAlign: 'center' }}>
              <div style={{ fontSize: 26, fontWeight: 700, color: r.color }}>{r.value.toLocaleString()}</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: r.color, marginTop: 4 }}>{r.label} RISK</div>
            </div>
          ))}
        </div>
      </div>

      {recurring.length > 0 && (
        <div className="card">
          <div className="section-title">
            <Repeat size={16} color="#ea580c" /> Recurring IOCs — seen multiple times
          </div>
          <table>
            <thead><tr><th>Type</th><th>Value</th><th>Malware</th><th>Times Seen</th></tr></thead>
            <tbody>
              {recurring.map(r => (
                <tr key={r.id} style={{ cursor: 'pointer' }} onClick={() => setDetail(r.value)}>
                  <td><span className="badge badge-blue">{r.ioc_type}</span></td>
                  <td className="mono">{r.value}</td>
                  <td>{r.malware || '—'}</td>
                  <td><span className="badge badge-high"><TrendingUp size={12} /> {r.times_seen}×</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {health?.recent_high_risk?.length > 0 && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="section-title"><AlertTriangle size={16} color="#dc2626" /> Recently seen high-risk intelligence</div>
          <table><thead><tr><th>Type</th><th>Indicator</th><th>Malware</th><th>Risk</th><th>Last seen</th></tr></thead>
            <tbody>{health.recent_high_risk.map(i => <tr key={`${i.ioc_type}-${i.value}`} style={{ cursor: 'pointer' }} onClick={() => setDetail(i.value)}><td><span className="badge badge-blue">{i.ioc_type}</span></td><td className="mono">{i.value}</td><td>{i.malware || '—'}</td><td><span className="badge badge-critical">{i.risk_score}</span></td><td>{i.last_seen ? new Date(i.last_seen).toLocaleString() : '—'}</td></tr>)}</tbody>
          </table>
        </div>
      )}
    </>
  )
}

/* ---------------- IOCs PAGE ---------------- */
function IOCsPage({ filter, setFilter, setDetail }) {
  const [data, setData] = useState(null)
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [error, setError] = useState(null)
  const searchRef = useRef(null)

  const handleSearchChange = (e) => {
    setSearch(e.target.value)
    if (searchRef.current) clearTimeout(searchRef.current)
    searchRef.current = setTimeout(() => {
      setDebouncedSearch(e.target.value)
      setPage(1)
    }, 300)
  }

  const loadData = () => {
    setError(null)
    getIOCs({ ...filter, search: debouncedSearch || undefined, limit: pageSize, offset: (page - 1) * pageSize })
      .then(setData)
      .catch(err => setError(err.message || 'Failed to load IOCs'))
  }

  useEffect(() => { loadData() }, [filter, debouncedSearch, page, pageSize])

  return (
    <>
      <div className="page-title">Indicators of Compromise</div>
      <div className="page-sub">
        {data ? `${data.total.toLocaleString()} indicators` : 'Loading…'}
        {Object.keys(filter).length > 0 && (
          <span className="badge badge-blue" style={{ marginLeft: 8, cursor: 'pointer' }} onClick={() => setFilter({})}>
            clear filters <X size={12} />
          </span>
        )}
      </div>

      <ErrorBanner message={error} onRetry={loadData} />
      <div className="filters">
        <div style={{ position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: 10, top: 10, color: '#6b7688' }} />
          <input className="input" style={{ paddingLeft: 34 }} placeholder="Search IOC value…"
            value={search} onChange={handleSearchChange} />
        </div>
        <select className="select" value={filter.ioc_type || ''}
          onChange={e => setFilter({ ...filter, ioc_type: e.target.value || undefined })}>
          <option value="">All types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="md5">MD5</option>
          <option value="sha256">SHA256</option>
          <option value="sha1">SHA1</option>
        </select>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {!data ? <div className="loading">Loading…</div> : (
          <table>
            <thead><tr><th>Type</th><th>Value</th><th>Malware</th><th>Reason</th><th>Seen</th></tr></thead>
            <tbody>
              {data.data.map(i => (
                <tr key={i.id} style={{ cursor: 'pointer' }} onClick={() => setDetail(i.value)}>
                  <td><span className="badge badge-blue">{i.ioc_type}</span></td>
                  <td className="mono">{i.value}</td>
                  <td>{i.malware || '—'}</td>
                  <td style={{ maxWidth: 340, color: '#6b7688' }}>{(i.reason || '').slice(0, 80)}</td>
                  <td><span className="badge badge-gray">{i.times_seen}×</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && data.total > 0 && (
          <div className="pagination">
            <div style={{ color: '#6b7688', fontSize: 13 }}>Showing {Math.min((page - 1) * pageSize + 1, data.total)} - {Math.min(page * pageSize, data.total)} of {data.total.toLocaleString()} indicators</div>
            <div className="pagination-controls">
              <button className="page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}><ChevronLeft size={16} /> Prev</button>
              <span style={{ fontSize: 13, fontWeight: 500, margin: '0 8px' }}>Page {page}</span>
              <button className="page-btn" disabled={page * pageSize >= data.total} onClick={() => setPage(p => p + 1)}>Next <ChevronRight size={16} /></button>
              <select className="select" style={{ marginLeft: 16, padding: '4px 8px' }} value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}>
                <option value={20}>20 / page</option>
                <option value={50}>50 / page</option>
                <option value={100}>100 / page</option>
              </select>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

/* ---------------- CVEs PAGE ---------------- */
function CVEsPage({ setCveDetail }) {
  const [data, setData] = useState(null)
  const [sev, setSev] = useState('')
  const [kevOnly, setKevOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [error, setError] = useState(null)

  const loadData = () => {
    setError(null)
    getCVEs({ severity: sev || undefined, kev_only: kevOnly, limit: pageSize, offset: (page - 1) * pageSize })
      .then(setData)
      .catch(err => setError(err.message || 'Failed to load CVEs'))
  }

  useEffect(() => { loadData() }, [sev, kevOnly, page, pageSize])

  return (
    <>
      <div className="page-title">Vulnerabilities (CVEs)</div>
      <div className="page-sub">{data ? `${data.total.toLocaleString()} CVEs` : 'Loading…'} · KEV = actively exploited</div>

      <ErrorBanner message={error} onRetry={loadData} />
      <ErrorBanner message={error} onRetry={loadData} />
      <div className="filters">
        <select className="select" value={sev} onChange={e => setSev(e.target.value)}>
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <label className="badge badge-gray" style={{ cursor: 'pointer', padding: '8px 12px' }}>
          <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} />
          &nbsp;Actively exploited only
        </label>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {!data ? <div className="loading">Loading…</div> : (
          <table>
            <thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Status</th><th>Description</th></tr></thead>
            <tbody>
              {data.data.map(c => (
                <tr key={c.cve_id} style={{ cursor: 'pointer' }} onClick={() => setCveDetail(c)}>
                  <td className="mono" style={{ fontWeight: 600 }}>{c.cve_id}</td>
                  <td style={{ fontWeight: 600 }}>{c.cvss_score ?? '—'}</td>
                  <td><span className={`badge ${severityBadge(c.severity)}`}>{c.severity || '—'}</span></td>
                  <td>{c.kev_listed && <span className="badge badge-critical">KEV</span>}</td>
                  <td style={{ maxWidth: 380, color: '#6b7688' }}>{c.description ? `${c.description.slice(0, 90)}${c.description.length > 90 ? '…' : ''}` : 'NVD details pending'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && data.total > 0 && (
          <div className="pagination">
            <div style={{ color: '#6b7688', fontSize: 13 }}>Showing {Math.min((page - 1) * pageSize + 1, data.total)} - {Math.min(page * pageSize, data.total)} of {data.total.toLocaleString()} indicators</div>
            <div className="pagination-controls">
              <button className="page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}><ChevronLeft size={16} /> Prev</button>
              <span style={{ fontSize: 13, fontWeight: 500, margin: '0 8px' }}>Page {page}</span>
              <button className="page-btn" disabled={page * pageSize >= data.total} onClick={() => setPage(p => p + 1)}>Next <ChevronRight size={16} /></button>
              <select className="select" style={{ marginLeft: 16, padding: '4px 8px' }} value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}>
                <option value={20}>20 / page</option>
                <option value={50}>50 / page</option>
                <option value={100}>100 / page</option>
              </select>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

function CVEDetailPanel({ cve, onClose }) {
  const [d, setD] = useState(null)
  useEffect(() => { getCVEDetail(cve.cve_id).then(setD).catch(() => setD({ error: true })) }, [cve])

  const cveData = d?.cve || cve

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, width: 480, height: '100vh', background: '#fff',
      borderLeft: '1px solid #e4e8ee', boxShadow: '-4px 0 24px rgba(16,24,40,0.08)',
      padding: 24, overflowY: 'auto', zIndex: 100,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>CVE Details</div>
        <X size={20} style={{ cursor: 'pointer' }} onClick={onClose} />
      </div>

      {!d && !d?.error && <div className="loading">Loading full details…</div>}

      <div className="card">
        <div className="mono" style={{ fontSize: 18, fontWeight: 700 }}>{cveData.cve_id}</div>
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <span className={`badge ${severityBadge(cveData.severity)}`}>{cveData.severity || 'NVD pending'}</span>
          {cveData.cvss_score != null && <span className="badge badge-gray">CVSS {cveData.cvss_score}</span>}
          {cveData.kev_listed && <span className="badge badge-critical" style={{ fontSize: 13, padding: '4px 8px' }}>CISA KEV</span>}
        </div>
      </div>

      <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>Full Description</div>
      <div style={{ fontSize: 14, lineHeight: 1.65, color: '#4b5563' }}>
        {cveData.description || 'NVD enrichment is pending for this KEV entry. Its CVSS, severity, and full description will appear after the next NVD batch.'}
      </div>
      {cveData.published && <DetailRow label="Published" value={String(cveData.published).slice(0, 19).replace('T', ' ')} />}

      <a href={`https://nvd.nist.gov/vuln/detail/${cveData.cve_id}`} target="_blank" rel="noopener noreferrer" className="ext-link-badge" style={{ marginTop: 20, padding: '8px 16px', background: '#2563eb', color: '#fff', border: 'none' }}>
        View on NVD <ExternalLink size={14} />
      </a>

      {d && d.references && d.references.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>References</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {d.references.map((r, i) => (
              <a key={i} href={r} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, color: '#2563eb', wordBreak: 'break-all' }}>{r}</a>
            ))}
          </div>
        </>
      )}

      {d && d.affected_products && d.affected_products.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>Affected Products</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {d.affected_products.map((p, i) => <span key={i} className="tag-chip">{p}</span>)}
          </div>
        </>
      )}
    </div>
  )
}

/* ---------------- LEVEL 2: CORRELATIONS ---------------- */
function CorrelationsPage({ setCorrelationDetail }) {
  const [summary, setSummary] = useState(null)
  const [clusters, setClusters] = useState(null)
  const [search, setSearch] = useState('')
  const [error, setError] = useState(null)

  const load = () => {
    setError(null)
    Promise.all([
      getCorrelationSummary(),
      getCorrelationClusters({ search: search || undefined, limit: 50 }),
    ]).then(([nextSummary, nextClusters]) => {
      setSummary(nextSummary)
      setClusters(nextClusters)
    }).catch(err => setError(err.message || 'Failed to load correlation data'))
  }

  useEffect(() => {
    const timer = setTimeout(load, search ? 250 : 0)
    return () => clearTimeout(timer)
  }, [search])

  const counts = summary?.counts || {}
  const cards = [
    ['IOC → Malware', counts.ioc_malware_links, '#2563eb'],
    ['Malware families', counts.malware_families, '#dc2626'],
    ['Sightings', counts.sighting_links, '#ea580c'],
    ['Actor → Software', counts.actor_software_links, '#7c3aed'],
    ['ATT&CK mappings', counts.attack_technique_links, '#0891b2'],
  ]

  return (
    <>
      <div className="page-title">Threat Correlation</div>
      <div className="page-sub">Evidence-backed links across indicators, malware, actors, sightings, reports, CVEs and ATT&CK</div>
      <ErrorBanner message={error} onRetry={load} />

      <div className="correlation-stats">
        {cards.map(([label, value, color]) => (
          <div className="stat-card compact" key={label} style={{ '--accent': color }}>
            <div className="stat-value" style={{ color }}>{Number(value || 0).toLocaleString()}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      {summary?.evidence?.length > 0 && (
        <div className="card evidence-card">
          <div className="section-title"><Network size={17} color="#2563eb" /> Evidence graph coverage</div>
          <div className="evidence-flow">
            {summary.evidence.map(e => (
              <div className="evidence-edge" key={`${e.subject_type}-${e.predicate}-${e.object_type}`}>
                <span>{e.subject_type}</span><strong>→</strong><span>{e.object_type}</span>
                <small>{Number(e.edge_count).toLocaleString()} {e.predicate.replaceAll('_', ' ')}</small>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0, marginTop: 20 }}>
        <div className="table-toolbar">
          <div>
            <div className="section-title" style={{ marginBottom: 2 }}>Malware-centered investigation clusters</div>
            <div className="stat-label">Click a family to follow its evidence chain</div>
          </div>
          <div style={{ position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: 10, top: 10, color: '#6b7688' }} />
            <input className="input" style={{ paddingLeft: 34 }} placeholder="Search malware…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>
        {!clusters ? <div className="loading">Building correlation clusters…</div> : clusters.length === 0 ? (
          <div className="loading">No matching evidence cluster.</div>
        ) : (
          <div className="table-scroll"><table>
            <thead><tr><th>Malware</th><th>IOCs</th><th>High Risk</th><th>Sightings</th><th>Actors</th><th>CVEs</th><th>Sources</th><th>Last Seen</th></tr></thead>
            <tbody>{clusters.map(c => {
              const actorNames = [...new Set(c.actors || [])]
              return <tr key={c.malware_key} style={{ cursor: 'pointer' }} onClick={() => setCorrelationDetail(c.malware)}>
                <td><span className="tag-chip malware">{c.malware}</span></td>
                <td><strong>{c.ioc_count}</strong></td>
                <td><span className={`badge ${c.high_risk_count ? 'badge-critical' : 'badge-gray'}`}>{c.high_risk_count}</span></td>
                <td>{c.sighting_count}</td>
                <td>{actorNames.length ? actorNames.slice(0, 2).map(a => <span key={a} className="tag-chip alias" style={{ margin: 2 }}>{a}</span>) : <span className="stat-label">No proven link</span>}</td>
                <td><span className={`badge ${c.cve_count ? 'badge-high' : 'badge-gray'}`}>{c.cve_count}</span></td>
                <td>{(c.sources || []).slice(0, 3).map(s => <span key={s} className="badge badge-gray" style={{ margin: 2 }}>{s}</span>)}</td>
                <td>{c.last_seen ? new Date(c.last_seen).toLocaleDateString() : '—'}</td>
              </tr>
            })}</tbody>
          </table></div>
        )}
      </div>
    </>
  )
}

function CorrelationDetailPanel({ name, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    getMalwareCorrelation(name).then(setData).catch(err => setError(err.message || 'Unable to load correlation'))
  }, [name])

  return (
    <div className="detail-panel correlation-panel">
      <div className="panel-header">
        <div><div className="stat-label">Correlation investigation</div><div style={{ fontSize: 20, fontWeight: 700 }}>{name}</div></div>
        <X size={20} style={{ cursor: 'pointer' }} onClick={onClose} />
      </div>
      {error ? <ErrorBanner message={error} /> : !data ? <div className="loading">Following evidence links…</div> : (
        <>
          <div className="correlation-chain">
            <span>IOCs <strong>{data.iocs.length}</strong></span><ChevronRight size={15} />
            <span>Malware</span><ChevronRight size={15} />
            <span>Actors <strong>{data.actors.length}</strong></span><ChevronRight size={15} />
            <span>Techniques <strong>{data.techniques.length}</strong></span>
          </div>

          <div className="section-title panel-section">Observed by</div>
          <div className="grid grid-2">
            {data.sources.map(s => <div className="mini-evidence" key={s.source}><strong>{s.source}</strong><span>{s.sightings} sightings</span></div>)}
          </div>

          <div className="section-title panel-section">Linked actors</div>
          {data.actors.length === 0 ? <div className="empty-evidence">No evidence-backed actor link is stored for this malware yet.</div> : data.actors.map(a => (
            <div className="card evidence-record" key={`${a.name}-${a.evidence}`}>
              <div><strong>{a.name}</strong>{a.mitre_id && <span className="badge badge-blue" style={{ marginLeft: 8 }}>{a.mitre_id}</span>}</div>
              <div className="stat-label">Evidence: {a.evidence}</div>
            </div>
          ))}

          {data.techniques.length > 0 && <>
            <div className="section-title panel-section">Actor techniques</div>
            <div className="chip-cloud">{data.techniques.slice(0, 40).map(t => (
              <a className="tag-chip alias" href={t.source_url} target="_blank" rel="noreferrer" key={`${t.group_name}-${t.technique_id}`} title={`${t.group_name}: ${t.technique_name}`}>
                {t.technique_id} · {t.technique_name}
              </a>
            ))}</div>
          </>}

          <div className="section-title panel-section">Indicators</div>
          <div className="table-scroll"><table><thead><tr><th>Type</th><th>Value</th><th>Risk</th><th>Sources</th></tr></thead>
            <tbody>{data.iocs.slice(0, 50).map(i => <tr key={i.id}><td><span className="badge badge-blue">{i.ioc_type}</span></td><td className="mono" style={{ maxWidth: 240, wordBreak: 'break-all' }}>{i.value}</td><td><span className={`badge ${i.risk_level === 'HIGH' ? 'badge-critical' : i.risk_level === 'MEDIUM' ? 'badge-high' : 'badge-low'}`}>{i.risk_score}</span></td><td>{(i.sources || []).join(', ')}</td></tr>)}</tbody>
          </table></div>

          <div className="section-title panel-section">Related reporting & CVEs</div>
          {data.articles.length === 0 && data.cves.length === 0 ? <div className="empty-evidence">No report or CVE co-mention has been observed. This absence is shown instead of inferring a relationship.</div> : <>
            {data.cves.map(c => <div className="mini-evidence" key={c.cve_id}><strong>{c.cve_id}</strong><span>{c.severity || 'Unrated'} {c.kev_listed ? '· CISA KEV' : ''}</span></div>)}
            {data.articles.map(a => <a className="card evidence-record evidence-link" href={a.link} target="_blank" rel="noreferrer" key={a.id}><strong>{a.title}</strong><span className="stat-label">{a.source || 'Threat report'}</span></a>)}
          </>}
        </>
      )}
    </div>
  )
}

/* ---------------- LEVEL 2: MITRE ATT&CK ---------------- */
function AttackPage({ setAptDetail }) {
  const [data, setData] = useState(null)
  const [search, setSearch] = useState('')
  const [error, setError] = useState(null)

  const load = () => {
    setError(null)
    getAttackOverview({ search: search || undefined }).then(setData).catch(err => setError(err.message || 'Failed to load ATT&CK coverage'))
  }
  useEffect(() => {
    const timer = setTimeout(load, search ? 250 : 0)
    return () => clearTimeout(timer)
  }, [search])

  const maxMappings = Math.max(...(data?.tactics || []).map(t => t.mappings), 1)
  return (
    <>
      <div className="page-title">MITRE ATT&CK Coverage</div>
      <div className="page-sub">Enterprise ATT&CK groups, tactics, techniques and software relationships synchronized from MITRE</div>
      <ErrorBanner message={error} onRetry={load} />
      {!data ? <div className="loading">Loading ATT&CK matrix…</div> : <>
        <div className="correlation-stats attack-stats">
          {[
            ['Mapped groups', data.stats.mapped_groups, '#0891b2'], ['Unique techniques', data.stats.techniques, '#7c3aed'],
            ['Group-technique links', data.stats.group_technique_links, '#2563eb'], ['Software', data.stats.software, '#dc2626'],
            ['Group-software links', data.stats.group_software_links, '#ea580c'],
          ].map(([label, value, color]) => <div className="stat-card compact" key={label} style={{ '--accent': color }}><div className="stat-value" style={{ color }}>{Number(value || 0).toLocaleString()}</div><div className="stat-label">{label}</div></div>)}
        </div>

        <div className="grid attack-layout">
          <div className="card">
            <div className="section-title"><Map size={17} color="#7c3aed" /> Tactic coverage</div>
            <div className="tactic-list">{data.tactics.map(t => <div className="tactic-row" key={t.tactic}>
              <div><strong>{t.tactic}</strong><span>{t.groups} groups · {t.techniques} techniques</span></div>
              <div className="coverage-track"><div style={{ width: `${Math.max(5, t.mappings / maxMappings * 100)}%` }} /></div>
              <b>{t.mappings}</b>
            </div>)}</div>
          </div>
          <div className="card" style={{ padding: 0 }}>
            <div className="section-title" style={{ padding: '20px 20px 0' }}>Most-used techniques</div>
            <div className="table-scroll"><table><thead><tr><th>Technique</th><th>Groups</th><th>Tactics</th></tr></thead><tbody>
              {data.top_techniques.map(t => <tr key={t.technique_id}><td><a href={t.source_url} target="_blank" rel="noreferrer"><strong>{t.technique_id}</strong></a><div className="stat-label">{t.technique_name}</div></td><td><span className="badge badge-blue">{t.group_count}</span></td><td>{(t.tactics || []).slice(0, 2).map(x => <span className="tag-chip alias" style={{ margin: 2 }} key={x}>{x}</span>)}</td></tr>)}
            </tbody></table></div>
          </div>
        </div>

        <div className="table-toolbar attack-toolbar">
          <div><div className="section-title" style={{ marginBottom: 2 }}>Threat actor matrix</div><div className="stat-label">Select a group to inspect techniques and evidence</div></div>
          <div style={{ position: 'relative' }}><Search size={16} style={{ position: 'absolute', left: 10, top: 10, color: '#6b7688' }} /><input className="input" style={{ paddingLeft: 34 }} placeholder="Search group or MITRE ID…" value={search} onChange={e => setSearch(e.target.value)} /></div>
        </div>
        <div className="attack-group-grid">{data.groups.map(g => <div className="stat-card attack-group" key={g.name} onClick={() => setAptDetail(g.name)}>
          <div className="attack-group-head"><div><strong>{g.name}</strong><div className="stat-label">{g.mitre_id || 'Community actor'}</div></div><ChevronRight size={18} /></div>
          <div className="attack-counts"><span><b>{g.technique_count}</b> techniques</span><span><b>{g.software_count}</b> software</span></div>
          <div className="chip-cloud">{(g.tactics || []).slice(0, 4).map(t => <span className="tag-chip alias" key={t}>{t}</span>)}</div>
        </div>)}</div>
      </>}
    </>
  )
}

/* ---------------- LEVEL 2: AI INVESTIGATION ---------------- */
function InvestigationPage() {
  const [entityType, setEntityType] = useState('malware')
  const [value, setValue] = useState('AsyncRAT')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const examples = {
    malware: 'AsyncRAT', ioc: '45.78.201.248', apt: 'APT29', cve: 'CVE-2005-2773',
  }
  const run = async (e) => {
    e?.preventDefault()
    if (!value.trim()) return
    setLoading(true); setError(null); setResult(null)
    try { setResult(await investigateEntity(entityType, value.trim())) }
    catch (err) { setError(err.response?.data?.detail || err.message || 'Investigation failed') }
    finally { setLoading(false) }
  }

  const evidence = result?.evidence || {}
  const evidenceCards = result ? (
    result.entity_type === 'malware' ? [
      ['IOCs', evidence.ioc_count], ['Actors', evidence.actor_count], ['Techniques', evidence.technique_count],
      ['CVEs', evidence.cve_count], ['Reports', evidence.report_count],
    ] : result.entity_type === 'ioc' ? [
      ['Sightings', evidence.sightings?.length || 0], ['Enrichment', evidence.enrichment ? 'Available' : 'Pending'],
    ] : result.entity_type === 'apt' ? [
      ['Techniques', evidence.techniques?.length || 0], ['Reports', evidence.articles?.length || 0],
    ] : [['CVSS', evidence.cvss_score ?? 'Pending'], ['Severity', evidence.severity || 'Pending'], ['CISA KEV', evidence.kev_listed ? 'Yes' : 'No']]
  ) : []

  return (
    <>
      <div className="page-title">AI-Assisted Investigation</div>
      <div className="page-sub">Read-only analyst reports grounded in the platform’s stored evidence</div>
      <div className="investigation-hero card">
        <div>
          <div className="section-title"><Sparkles size={18} color="#7c3aed" /> Start an evidence-led investigation</div>
          <div className="stat-label">Choose an entity and the assistant will correlate sightings, enrichment, reports, CVEs and ATT&CK context. It cannot change data or trigger response actions.</div>
        </div>
        <form className="investigation-form" onSubmit={run}>
          <select className="select" value={entityType} onChange={e => { setEntityType(e.target.value); setValue(examples[e.target.value]); setResult(null) }}>
            <option value="malware">Malware</option><option value="ioc">IOC</option><option value="apt">APT / threat actor</option><option value="cve">CVE</option>
          </select>
          <input className="input" value={value} onChange={e => setValue(e.target.value)} placeholder={`Example: ${examples[entityType]}`} />
          <button className="investigate-btn" disabled={loading || !value.trim()}><BrainCircuit size={17} /> {loading ? 'Investigating…' : 'Investigate'}</button>
        </form>
      </div>
      <ErrorBanner message={error} onRetry={run} />
      {loading && <div className="loading">Collecting evidence and asking the local model…</div>}
      {result && <>
        <div className="investigation-evidence">
          {evidenceCards.map(([label, amount]) => <div className="mini-evidence" key={label}><strong>{amount ?? 0}</strong><span>{label}</span></div>)}
        </div>
        <div className="card investigation-report">
          <div className="report-header"><div><div className="section-title" style={{ marginBottom: 3 }}>Analyst report: {result.value}</div><div className="stat-label">Generated by {result.generated_by === 'ollama' ? 'local Ollama model' : 'deterministic fallback'} · evidence-grounded · read-only</div></div><span className="badge badge-low">No actions executed</span></div>
          <div className="report-body">{result.analysis}</div>
        </div>
      </>}
    </>
  )
}

/* ---------------- LEVEL 2: SIEM INTEGRATION ---------------- */
function SIEMPage({ setDetail, setCveDetail }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const load = () => {
    setError(null)
    getSIEMOverview().then(setData).catch(err => setError(err.message || 'Failed to load SIEM events'))
  }
  useEffect(() => { load() }, [])

  return (
    <>
      <div className="page-title">SIEM Intelligence Matching</div>
      <div className="page-sub">Wazuh/Elastic events matched against local IOC and CVE intelligence</div>
      <ErrorBanner message={error} onRetry={load} />
      {!data ? <div className="loading">Loading SIEM status…</div> : <>
        {!data.configured && <div className="siem-setup-banner"><RadioTower size={20} /><div><strong>Ingestion endpoint is safely disabled</strong><span>Set a long random SIEM_INGEST_TOKEN in backend/.env and restart the API before connecting Wazuh or Elastic.</span></div></div>}
        <div className="correlation-stats siem-stats">
          {[
            ['Total events', data.stats.total_events, '#2563eb'], ['Matched events', data.stats.matched_events, '#7c3aed'],
            ['CTI matches', data.stats.total_matches, '#dc2626'], ['Last 24 hours', data.stats.events_24h, '#0891b2'],
          ].map(([label, amount, color]) => <div className="stat-card compact" key={label} style={{ '--accent': color }}><div className="stat-value" style={{ color }}>{Number(amount || 0).toLocaleString()}</div><div className="stat-label">{label}</div></div>)}
        </div>

        <div className="card" style={{ padding: 0, marginBottom: 20 }}>
          <div className="section-title" style={{ padding: '20px 20px 0' }}><Shield size={17} color="#dc2626" /> Recent CTI matches</div>
          {data.recent_matches.length === 0 ? <div className="empty-evidence" style={{ margin: 20 }}>No SIEM alerts have matched stored intelligence yet.</div> : <div className="table-scroll"><table><thead><tr><th>Entity</th><th>Matched value</th><th>Risk</th><th>Event</th><th>Agent</th><th>Source</th></tr></thead><tbody>
            {data.recent_matches.map((m, i) => <tr key={`${m.event_id}-${m.entity_type}-${m.entity_value}-${i}`} style={{ cursor: 'pointer' }} onClick={() => m.entity_type === 'ioc' ? setDetail(m.entity_value) : setCveDetail({ cve_id: m.entity_value })}>
              <td><span className="badge badge-blue">{m.entity_type}</span></td><td className="mono">{m.entity_value}</td><td><span className={`badge ${m.risk_level === 'HIGH' || m.risk_level === 'CRITICAL' ? 'badge-critical' : 'badge-gray'}`}>{m.risk_level || m.risk_score || '—'}</span></td><td>{m.title}</td><td>{m.agent_name || '—'}</td><td>{m.source}</td>
            </tr>)}
          </tbody></table></div>}
        </div>

        <div className="card" style={{ padding: 0 }}>
          <div className="section-title" style={{ padding: '20px 20px 0' }}><RadioTower size={17} color="#2563eb" /> Recent ingested events</div>
          {data.recent_events.length === 0 ? <div className="empty-evidence" style={{ margin: 20 }}>No events ingested. The Wazuh-compatible forwarder is ready after token configuration.</div> : <div className="table-scroll"><table><thead><tr><th>Time</th><th>Source</th><th>Rule</th><th>Level</th><th>Event</th><th>Agent</th><th>Matches</th></tr></thead><tbody>
            {data.recent_events.map(e => <tr key={e.id}><td>{e.event_timestamp ? new Date(e.event_timestamp).toLocaleString() : new Date(e.ingested_at).toLocaleString()}</td><td><span className="badge badge-gray">{e.source}</span></td><td className="mono">{e.rule_id || '—'}</td><td>{e.rule_level ?? '—'}</td><td>{e.title}</td><td>{e.agent_name || '—'}</td><td><span className={`badge ${e.match_count ? 'badge-critical' : 'badge-gray'}`}>{e.match_count}</span></td></tr>)}
          </tbody></table></div>}
        </div>
      </>}
    </>
  )
}

/* ---------------- APT PAGE ---------------- */
function APTPage({ setAptDetail }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const loadData = () => {
    setError(null)
    getAPT().then(setData).catch(err => setError(err.message || 'Failed to load APT groups'))
  }
  useEffect(() => { loadData() }, [])

  if (!data && !error) return <div className="loading">Loading…</div>

  return (
    <>
      <div className="page-title">Threat Groups & Actors</div>
      <div className="page-sub">Named APT, UNC, and TA groups explicitly extracted from intel articles</div>
      <ErrorBanner message={error} onRetry={loadData} />
      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        {data.map(g => (
          <div key={g.id} className="stat-card" style={{ cursor: 'pointer' }}
            onClick={() => setAptDetail(g.name)}>
            <div className="stat-icon" style={{ background: '#ecfeff' }}>
              <Users size={20} color="#0891b2" />
            </div>
            <div style={{ fontSize: 18, fontWeight: 700 }}>{g.name}</div>
            <div className="stat-label">Seen {g.times_seen}× · click for details</div>
          </div>
        ))}
      </div>
    </>
  )
}

function APTDetailPanel({ name, onClose }) {
  const [data, setData] = useState(null)
  useEffect(() => { getAPTDetail(name).then(setData).catch(() => setData({ error: true })) }, [name])
  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, width: 460, height: '100vh',
      background: '#fff', borderLeft: '1px solid #e4e8ee', boxShadow: '-4px 0 24px rgba(16,24,40,0.08)',
      padding: 24, overflowY: 'auto', zIndex: 100,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>{name} Details</div>
        <X size={20} style={{ cursor: 'pointer' }} onClick={onClose} />
      </div>
      {!data ? <div className="loading">Loading…</div> : data.error ? <div className="loading">Unable to load details.</div> : (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 20, fontWeight: 700 }}>{data.group.name}</div>
            <div className="stat-label" style={{ marginTop: 6 }}>Explicitly mentioned in {data.group.times_seen} ingested article(s)</div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 12 }}>
              {(data.group.aliases || []).map(a => <span key={a} className="tag-chip alias">{a}</span>)}
              {(data.group.target_sectors || []).map(s => <span key={s} className="tag-chip sector">{s}</span>)}
            </div>
            {data.group.origin_country && <div style={{ marginTop: 12, fontSize: 13 }}><span style={{ color: '#6b7688' }}>Origin:</span> {data.group.origin_country}</div>}
            {data.group.catalogued && data.group.description && <div style={{ marginTop: 12, fontSize: 13, lineHeight: 1.6, color: '#4b5563' }}>{data.group.description}</div>}
            {!data.group.catalogued && <div className="stat-label" style={{ marginTop: 12 }}>Profile not catalogued yet — evidence below is taken directly from the ingested source.</div>}
          </div>
          {data.techniques?.length > 0 && (
            <>
              <div className="section-title" style={{ fontSize: 14 }}>MITRE ATT&CK techniques</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7, marginBottom: 18 }}>
                {data.techniques.map(t => (
                  <a key={t.technique_id} href={t.source_url} target="_blank" rel="noreferrer" className="tag-chip alias" title={t.technique_name}>
                    {t.technique_id} · {t.technique_name}
                  </a>
                ))}
              </div>
            </>
          )}
          <div className="section-title" style={{ fontSize: 14 }}>Source Articles</div>
          {data.articles.length === 0 ? <div className="loading">No stored source excerpt is available.</div> : data.articles.map((a, i) => (
            <div key={i} className="card" style={{ marginBottom: 12 }}>
              <div style={{ fontWeight: 600, fontSize: 14 }}>{a.title}</div>
              {a.published && <div className="stat-label" style={{ marginTop: 4 }}>{a.published}</div>}
              {a.source && <div className="stat-label" style={{ marginTop: 6 }}>Source: {a.source}</div>}
              <div style={{ marginTop: 8, fontSize: 13, lineHeight: 1.55, color: '#4b5563' }}>{a.excerpt || 'No excerpt was stored for this source.'}</div>
              {a.link && <a href={a.link} target="_blank" rel="noreferrer" style={{ display: 'inline-flex', gap: 4, marginTop: 10, fontSize: 13 }}>Open source <ExternalLink size={14} /></a>}
            </div>
          ))}
        </>
      )}
    </div>
  )
}

/* ---------------- ARTICLES PAGE ---------------- */
function ArticlesPage() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const loadData = () => {
    setError(null)
    getArticles().then(setData).catch(err => setError(err.message || 'Failed to load articles'))
  }
  useEffect(() => { loadData() }, [])

  if (!data && !error) return <div className="loading">Loading…</div>

  return (
    <>
      <div className="page-title">Threat Feed</div>
      <div className="page-sub">Latest intel articles with extracted actors & malware</div>
      <ErrorBanner message={error} onRetry={loadData} />
      <div className="grid" style={{ gridTemplateColumns: '1fr' }}>
        {data.map((a, i) => (
          <div key={i} className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16 }}>
              <a href={a.link || '#'} target={a.link ? "_blank" : undefined} rel={a.link ? "noopener noreferrer" : undefined} style={{ fontWeight: 600, fontSize: 16, color: '#1a2233', textDecoration: 'none', transition: 'color 0.15s' }} onMouseOver={e => e.currentTarget.style.color = '#2563eb'} onMouseOut={e => e.currentTarget.style.color = '#1a2233'}>{a.title}</a>
              {a.published && <span style={{ fontSize: 12, color: '#6b7688', whiteSpace: 'nowrap' }}>{String(a.published).slice(0, 10)}</span>}
            </div>
            {a.summary && <div style={{ color: '#4b5563', marginTop: 10, lineHeight: 1.5 }}>{a.summary}</div>}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 14 }}>
              {(a.apt_groups || []).map(g => <span key={g} className="tag-chip alias" style={{ cursor: 'pointer' }}>{g}</span>)}
              {(a.malware || []).map(m => <span key={m} className="tag-chip malware" style={{ cursor: 'pointer' }}>{m}</span>)}
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

/* ---------------- DETAIL PANEL (drill-down) ---------------- */
function DetailPanel({ value, onClose }) {
  const [d, setD] = useState(null)
  useEffect(() => { getIOCDetail(value).then(setD) }, [value])

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, width: 440, height: '100vh',
      background: '#fff', borderLeft: '1px solid #e4e8ee', boxShadow: '-4px 0 24px rgba(16,24,40,0.08)',
      padding: 24, overflowY: 'auto', zIndex: 100,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>IOC Detail</div>
        <X size={20} style={{ cursor: 'pointer' }} onClick={onClose} />
      </div>
      {!d || d.error ? <div className="loading">Loading…</div> : (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 15, fontWeight: 600, wordBreak: 'break-all' }}>{d.ioc.value}</div>
            <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
              <span className="badge badge-blue">{d.ioc.ioc_type}</span>
              {d.ioc.is_active && <span className="badge badge-low">active</span>}
              <span className="badge badge-gray">seen {d.ioc.times_seen}×</span>
            </div>
          </div>

          <DetailRow label="Malware" value={d.ioc.malware} />
          <DetailRow label="Threat Type" value={d.ioc.threat_type} />
          <DetailRow label="Confidence" value={d.ioc.confidence != null ? `${d.ioc.confidence}%` : null} />
          <DetailRow label="First Seen" value={d.ioc.first_seen?.slice(0, 19).replace('T', ' ')} />
          <DetailRow label="Last Seen" value={d.ioc.last_seen?.slice(0, 19).replace('T', ' ')} />

          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 12, color: '#6b7688', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Why flagged</div>
            <div style={{ fontSize: 13, lineHeight: 1.6 }}>{d.ioc.reason || '—'}</div>
          </div>

          {d.external_links && (
            <div style={{ marginTop: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {Object.entries(d.external_links).map(([k, v]) => {
                const label = { virustotal: 'VirusTotal', shodan: 'Shodan', abuseipdb: 'AbuseIPDB', urlscan: 'URLScan', malwarebazaar: 'MalwareBazaar' }[k.toLowerCase()] || k
                return (
                  <a key={k} href={v} target="_blank" rel="noopener noreferrer" className="ext-link-badge">
                    {label} <ExternalLink size={12} />
                  </a>
                )
              })}
            </div>
          )}

          {d.enrichment && (
            <>
              <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>Enrichment</div>
              {d.enrichment.abuse_score != null && (
                <DetailRow label="Abuse Score" value={
                  <span className={"badge " + (d.enrichment.abuse_score >= 50 ? "badge-critical" : d.enrichment.abuse_score >= 15 ? "badge-high" : "badge-low")}>
                    {d.enrichment.abuse_score}% ({d.enrichment.abuse_reports || 0} reports)
                  </span>
                } />
              )}
              <DetailRow label="Country" value={d.enrichment.abuse_country} />
              <DetailRow label="ISP" value={d.enrichment.abuse_isp} />
              <DetailRow label="Usage" value={d.enrichment.abuse_usage} />
              {d.enrichment.shodan_ports && d.enrichment.shodan_ports !== 'none' && (
                <DetailRow label="Open Ports" value={
                  <span className="mono" style={{ fontSize: 12 }}>{d.enrichment.shodan_ports}</span>
                } />
              )}
              <DetailRow label="Shodan Org" value={d.enrichment.shodan_org && d.enrichment.shodan_org !== 'none' ? d.enrichment.shodan_org : null} />
            </>
          )}

          {d.enrichment && (d.enrichment.vt_malicious != null || d.enrichment.vt_reputation != null) && (
            <>
              <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>VirusTotal</div>
              {d.enrichment.vt_malicious != null && <DetailRow label="Malicious detections" value={<span className={"badge " + (d.enrichment.vt_malicious > 0 ? "badge-critical" : "badge-low")}>{d.enrichment.vt_malicious}</span>} />}
              {d.enrichment.vt_suspicious != null && <DetailRow label="Suspicious detections" value={d.enrichment.vt_suspicious} />}
              {d.enrichment.vt_reputation != null && <DetailRow label="Reputation" value={d.enrichment.vt_reputation} />}
              {d.enrichment.vt_link && <a href={d.enrichment.vt_link} target="_blank" rel="noopener noreferrer" className="ext-link-badge" style={{ marginTop: 10 }}>Open VirusTotal <ExternalLink size={12} /></a>}
            </>
          )}

          {d.enrichment && (d.enrichment.greynoise_noise != null || d.enrichment.greynoise_riot != null) && (
            <>
              <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>GreyNoise</div>
              <DetailRow label="Internet scanner / noise" value={d.enrichment.greynoise_noise ? 'Yes' : 'No'} />
              <DetailRow label="RIOT allowlist" value={d.enrichment.greynoise_riot ? 'Yes' : 'No'} />
              <DetailRow label="Classification" value={d.enrichment.greynoise_classification} />
              <DetailRow label="Organization" value={d.enrichment.greynoise_name} />
              {d.enrichment.greynoise_link && <a href={d.enrichment.greynoise_link} target="_blank" rel="noopener noreferrer" className="ext-link-badge" style={{ marginTop: 10 }}>Open GreyNoise <ExternalLink size={12} /></a>}
            </>
          )}

          <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>Sighting History</div>
          {d.sightings.map((s, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f1f3f7' }}>
              <span className="badge badge-gray">{s.source}</span>
              <span style={{ fontSize: 12, color: '#6b7688' }}>{s.seen_at?.slice(0, 19).replace('T', ' ')}</span>
            </div>
          ))}
        </>
      )}
    </div>
  )
}

function DetailRow({ label, value }) {
  if (!value) return null
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f1f3f7' }}>
      <span style={{ fontSize: 13, color: '#6b7688' }}>{label}</span>
      <span style={{ fontSize: 13, fontWeight: 500, textAlign: 'right' }}>{value}</span>
    </div>
  )
}
