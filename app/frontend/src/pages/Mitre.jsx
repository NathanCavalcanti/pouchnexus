import { useState } from 'react'
import { Search, ExternalLink, AlertTriangle } from 'lucide-react'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// ── Tactic colour map ─────────────────────────────────────────────────────
const TACTIC_COLORS = {
  'Initial Access':        '#f97316',
  'Execution':             '#ef4444',
  'Persistence':           '#a855f7',
  'Privilege Escalation':  '#ec4899',
  'Defense Evasion':       '#8b5cf6',
  'Credential Access':     '#06b6d4',
  'Discovery':             '#3b82f6',
  'Lateral Movement':      '#22c55e',
  'Collection':            '#eab308',
  'Command and Control':   '#f43f5e',
  'Exfiltration':          '#14b8a6',
  'Impact':                '#dc2626',
  'Resource Development':  '#6366f1',
  'Reconnaissance':        '#64748b',
}
function tacticColor(name) { return TACTIC_COLORS[name] || 'var(--accent)' }

// ── Technique card (lookup mode) ─────────────────────────────────────────
function TechCard({ tech }) {
  const tactic = tech.tactics?.[0]
  const color  = tacticColor(tactic?.tactic)
  return (
    <div className="analysis-section" style={{ borderLeft: `3px solid ${color}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{tech.id}</span>
            <span className="mitre-badge" style={{ background: `${color}22`, color, borderColor: `${color}66` }}>
              {tactic?.tactic || 'Unknown Tactic'}
            </span>
          </div>
          <div style={{ fontSize: 17, fontWeight: 700, marginBottom: 8 }}>{tech.name}</div>
          {tech.description && (
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, maxHeight: 120, overflow: 'hidden', WebkitLineClamp: 4, display: '-webkit-box', WebkitBoxOrient: 'vertical' }}>
              {tech.description}
            </p>
          )}
        </div>
        <a
          href={tech.url || `https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}`}
          target="_blank"
          rel="noreferrer"
          className="btn btn-secondary"
          style={{ fontSize: 12, flexShrink: 0 }}
        >
          <ExternalLink size={12} /> MITRE
        </a>
      </div>
    </div>
  )
}

export default function Mitre() {
  const [lookupId, setLookupId] = useState('')
  const [looking,  setLooking]  = useState(false)
  const [lookResult,setLookResult]= useState(null)
  const [lookError, setLookError] = useState(null)

  const setQueryAndSearch = (id) => {
    setLookupId(id)
    // Small timeout to ensure state update before triggering search
    // but better to just call the API directly with the id
    handleLookup(null, id)
  }

  const handleLookup = async (e, overrideId = null) => {
    if (e) e.preventDefault()
    const id = overrideId || lookupId
    if (!id.trim()) return
    setLooking(true)
    setLookResult(null)
    setLookError(null)
    try {
      const res = await fetch(`${BASE}/api/v1/enrichment/mitre/${encodeURIComponent(id.trim().toUpperCase())}`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Not found')
      setLookResult(data)
    } catch (err) {
      setLookError(err.message)
    } finally {
      setLooking(false)
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">MITRE ATT&amp;CK</div>
          <div className="topbar-sub">Technique Lookup &amp; Enterprise Matrix</div>
        </div>
        <div className="topbar-actions">
          <a href="https://attack.mitre.org" target="_blank" rel="noreferrer" className="btn btn-secondary">
            <ExternalLink size={14} /> MITRE Website
          </a>
        </div>
      </div>

      <div className="page">
        <div className="form-panel">
          <form onSubmit={handleLookup} style={{ marginBottom: 24 }}>
            <div className="form-group">
              <label className="form-label" htmlFor="tech-id">Technique ID</label>
              <div style={{ display: 'flex', gap: 10 }}>
                <input
                  id="tech-id"
                  className="form-input"
                  placeholder="e.g. T1059  |  T1059.001  |  T1566.002"
                  value={lookupId}
                  onChange={e => setLookupId(e.target.value)}
                />
                <button className="btn btn-primary" type="submit" disabled={looking || !lookupId.trim()}>
                  {looking ? <span className="spinner" /> : <Search size={15} />}
                  {looking ? 'Searching…' : 'Lookup'}
                </button>
              </div>
            </div>
          </form>

          {/* Quick links */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 24 }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>Examples:</span>
            {['T1059.001', 'T1566.001', 'T1486', 'T1055', 'T1003.001', 'T1071.001'].map(id => (
              <button
                key={id}
                className="btn btn-secondary"
                style={{ fontSize: 11, padding: '4px 10px', fontFamily: 'var(--font-mono)' }}
                onClick={() => setQueryAndSearch(id)}
              >
                {id}
              </button>
            ))}
          </div>

          {lookError && (
            <div className="analysis-section" style={{ borderLeft: '3px solid var(--danger)' }}>
              <div style={{ color: 'var(--danger)', display: 'flex', gap: 8 }}>
                <AlertTriangle size={16} /> {lookError}
              </div>
            </div>
          )}

          {looking && (
            <div className="flex-center" style={{ padding: 60 }}>
              <div className="spinner" style={{ width: 32, height: 32 }} />
            </div>
          )}

          {lookResult && !looking && <TechCard tech={lookResult} />}
        </div>
      </div>
    </>
  )
}

