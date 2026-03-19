import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, CheckCircle, Clock, XCircle, Inbox, TrendingUp, RefreshCw } from 'lucide-react'
import { api } from '../api.js'
import { useApp } from '../context/AppContext'
import heroBg from '../assets/hero_bg.png'
import LanguageSelector from '../components/LanguageSelector.jsx'

function StatCard({ icon: Icon, value, label, color, bg }) {
  return (
    <div className="stat-card">
      <div className="stat-card-glow" style={{ background: color }}></div>
      <div className="stat-card-icon" style={{ background: bg }}>
        <Icon size={20} color={color} />
      </div>
      <div className="stat-card-value" style={{ color }}>{value ?? '—'}</div>
      <div className="stat-card-label">{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const { t } = useApp()
  const [stats, setStats]         = useState(null)
  const [recent, setRecent]       = useState([])
  const [loading, setLoading]     = useState(true)
  const navigate = useNavigate()

  const load = async () => {
    setLoading(true)
    try {
      const [s, r] = await Promise.all([
        api.getStats(),
        api.listIncidents({ limit: 8 }),
      ])
      setStats(s)
      setRecent(r)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Auto-refresh every 15s to catch background task completions
  useEffect(() => {
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  const by = stats?.by_status || {}

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">{t.dashboard}</div>
          <div className="topbar-sub">Real-time SOC operations overview</div>
        </div>
        <div className="topbar-actions">
          <LanguageSelector />
          <button className="btn btn-secondary" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spinner' : ''} />
            {t.refresh}
          </button>
          <button className="btn btn-primary" onClick={() => navigate('/submit')}>
            + {t.new_incident}
          </button>
        </div>
      </div>

      <div className="page">
        {/* Pro Max Hero */}
        <div className="hero-banner" style={{ backgroundImage: `linear-gradient(rgba(3, 6, 12, 0.4), rgba(3, 6, 12, 0.8)), url(${heroBg})` }}>
           <div className="hero-content">
             <h1>{t.hero_title}</h1>
             <p>{t.hero_sub}</p>
           </div>
        </div>

        {/* Stats */}
        <div className="stats-grid">
          <StatCard
            icon={Inbox}
            value={stats?.total}
            label={t.total_incidents}
            color="var(--accent)"
            bg="rgba(124,58,237,0.12)"
          />
          <StatCard
            icon={Clock}
            value={(by.pending ?? 0) + (by.analyzing ?? 0)}
            label={t.active_pending}
            color="var(--warn)"
            bg="rgba(251,191,36,0.1)"
          />
          <StatCard
            icon={CheckCircle}
            value={by.completed ?? 0}
            label={t.completed}
            color="var(--ok)"
            bg="rgba(16,185,129,0.1)"
          />
          <StatCard
            icon={XCircle}
            value={by.failed ?? 0}
            label={t.failed}
            color="var(--danger)"
            bg="rgba(239,68,68,0.1)"
          />
          <StatCard
            icon={ShieldAlert}
            value={stats?.by_severity?.critical ?? 0}
            label={t.critical_severity}
            color="#ff4d6d"
            bg="rgba(255,77,109,0.1)"
          />
          <StatCard
            icon={TrendingUp}
            value={stats?.by_severity?.high ?? 0}
            label={t.high_severity}
            color="#fb923c"
            bg="rgba(251,146,60,0.1)"
          />
        </div>

        {/* Recent incidents */}
        <div className="section-header">
          <div>
            <div className="section-title">{t.recent_incidents}</div>
            <div className="section-sub">Last 8 ingested events</div>
          </div>
          <button className="btn btn-ghost" onClick={() => navigate('/incidents')}>
            View all →
          </button>
        </div>

        <div className="table-container">
          {loading ? (
            <div className="flex-center" style={{ padding: 40 }}>
              <div className="spinner" />
            </div>
          ) : recent.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🛡️</div>
              <div className="empty-state-title">No incidents yet</div>
              <div className="empty-state-sub">
                Submit a log manually or configure a webhook to start ingesting alerts automatically.
              </div>
            </div>
          ) : (
            <>
              <table className="incident-table">
                <thead>
                  <tr>
                    <th>{t.status}</th>
                    <th>{t.source}</th>
                    <th>{t.severity}</th>
                    <th>{t.preview}</th>
                    <th>{t.created}</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map(inc => (
                    <tr key={inc.id} onClick={() => navigate('/incidents', { state: { openId: inc.id } })}>
                      <td><span className={`badge badge-${inc.status}`}>{inc.status}</span></td>
                      <td><span className="badge badge-unknown">{inc.source}</span></td>
                      <td><span className={`sev-${inc.severity}`}>{inc.severity?.toUpperCase()}</span></td>
                      <td><span className="truncate text-sm text-muted">{inc.raw_text?.slice(0, 80)}…</span></td>
                      <td className="text-xs text-muted mono">{new Date(inc.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="mobile-cards">
                {recent.map(inc => (
                  <div key={inc.id} className="mobile-incident-card" onClick={() => navigate('/incidents', { state: { openId: inc.id } })}>
                     <div className="card-header">
                       <span className={`badge badge-${inc.status}`}>{inc.status}</span>
                       <span className={`sev-${inc.severity ?? 'unknown'}`}>{(inc.severity ?? 'unknown').toUpperCase()}</span>
                     </div>
                     <div className="card-body">
                       <div style={{ fontWeight: 600, marginBottom: 4 }}>{inc.source}</div>
                       <div className="truncate mono text-xs">{inc.raw_text}</div>
                     </div>
                     <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8 }}>
                       <span className="text-xs text-muted">{new Date(inc.created_at).toLocaleTimeString()}</span>
                     </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Source breakdown */}
        {stats?.by_source && Object.keys(stats.by_source).length > 0 && (
          <>
            <div className="section-header" style={{ marginTop: 28 }}>
              <div className="section-title">Ingestion Sources</div>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {Object.entries(stats.by_source).map(([src, count]) => (
                <div key={src} className="stat-card" style={{ minWidth: 140, flex: '0 0 auto' }}>
                  <div className="stat-card-value" style={{ fontSize: 24 }}>{count}</div>
                  <div className="stat-card-label">{src}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </>
  )
}
