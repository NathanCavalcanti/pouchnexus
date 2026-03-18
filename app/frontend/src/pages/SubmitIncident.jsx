import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { SendHorizonal, AlertCircle, CheckCircle, Swords, AlertTriangle, ExternalLink, ChevronRight } from 'lucide-react'
import { api } from '../api.js'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const EXAMPLE = `Suspicious PowerShell execution detected on WORKSTATION-04:
powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA...
Source IP: 185.220.101.47
Target: malicious-domain.ru
File created: C:\\Users\\john\\AppData\\Local\\Temp\\payload.exe
SHA256: a3f5b2c1d4e6f7890abc1234567890abcdef1234567890abcdef1234567890ab
Wazuh rule 100002 triggered: Possible PowerShell encoded command`

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

// ── MappedTechCard Component ──────────────────────────────────────────────
function MappedTechCard({ tech, idx }) {
  const color = tacticColor(tech.tactic)
  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid ${color}44`,
      borderLeft: `3px solid ${color}`, borderRadius: 'var(--radius)',
      padding: '14px 16px', marginBottom: 10,
      animation: `fadeUp 0.3s ease ${idx * 0.05}s both`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span className="mono" style={{ color: 'var(--accent)', fontSize: 13, fontWeight: 700 }}>{tech.id}</span>
            <span style={{ fontSize: 13, fontWeight: 700 }}>{tech.name}</span>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
            {tech.tactic_id && (
              <span className="badge badge-unknown" style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}>{tech.tactic_id}</span>
            )}
            {tech.tactic && (
              <span className="badge" style={{ fontSize: 10, background: `${color}22`, color, border: `1px solid ${color}55` }}>
                {tech.tactic}
              </span>
            )}
          </div>
        </div>
        <a
          href={`https://attack.mitre.org/techniques/${(tech.id || '').replace('.', '/')}`}
          target="_blank"
          rel="noreferrer"
          style={{ color: 'var(--accent)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
        >
          <ExternalLink size={11} /> MITRE
        </a>
      </div>
      {tech.justification && (
        <div style={{
          fontSize: 12, color: 'var(--text-secondary)', borderLeft: '2px solid var(--border)',
          paddingLeft: 10, marginTop: 4, lineHeight: 1.5,
        }}>
          <ChevronRight size={11} style={{ display: 'inline', marginRight: 3, color: 'var(--accent)' }} />
          {tech.justification}
        </div>
      )}
    </div>
  )
}

export default function SubmitIncident() {
  const navigate = useNavigate()

  const [form, setForm] = useState({
    incident: '',
    source: 'manual',
    severity: 'unknown',
  })
  
  // Submit Full Pipeline State
  const [loading, setLoading] = useState(false)
  const [toast, setToast]     = useState(null)   // { type, msg }

  // AI TTP Mapper State
  const [mapping,  setMapping]  = useState(false)
  const [mapResult,setMapResult]= useState(null)
  const [mapError, setMapError] = useState(null)
  const pollRef                 = useRef(null)

  // Clear polling on unmount
  useEffect(() => () => clearInterval(pollRef.current), [])

  const showToast = (type, msg) => {
    setToast({ type, msg })
    setTimeout(() => setToast(null), 4000)
  }

  // Submit to main pipeline
  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.incident.trim()) return

    setLoading(true)
    try {
      const res = await api.analyzeManual(form)
      showToast('ok', `Queued for analysis · ID: ${res.incident_id}`)
      setTimeout(() => navigate('/incidents'), 1600)
    } catch (err) {
      showToast('err', err.message || 'Failed to submit incident')
    } finally {
      setLoading(false)
    }
  }

  // Analyze with TTP Mapper only
  const handleMapTTP = async () => {
    const text = form.incident.trim()
    if (!text) return
    setMapping(true)
    setMapResult(null)
    setMapError(null)

    try {
      const res  = await fetch(`${BASE}/api/v1/enrichment/mitre/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      })
      const job  = await res.json()
      if (!res.ok) throw new Error(job.detail || 'API error')

      // Poll for result
      pollRef.current = setInterval(async () => {
        const poll = await fetch(`${BASE}/api/v1/enrichment/mitre/analyze/${job.job_id}`)
        const data = await poll.json()
        if (data.status === 'completed') {
          clearInterval(pollRef.current)
          setMapResult(data.result)
          setMapping(false)
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current)
          setMapError(data.error || 'Analysis failed')
          setMapping(false)
        }
      }, 2000)
    } catch (err) {
      setMapError(err.message)
      setMapping(false)
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">New Incident</div>
          <div className="topbar-sub">Paste a log, alert, or event description for AI analysis</div>
        </div>
      </div>

      <div className="page">
        <div className="form-panel" style={{ maxWidth: 900, margin: '0 auto' }}>
          <form onSubmit={handleSubmit}>
            {/* Incident text */}
            <div className="form-group">
              <label className="form-label" htmlFor="incident-text">
                Incident Log / Event Description *
              </label>
              <textarea
                id="incident-text"
                className="form-textarea"
                placeholder={EXAMPLE}
                value={form.incident}
                onChange={e => setForm({ ...form, incident: e.target.value })}
                required
                minLength={10}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {/* Source (Fixed to Manual) */}
              <div className="form-group" style={{ opacity: 0.8 }}>
                <label className="form-label" htmlFor="source-select">Source</label>
                <select
                  id="source-select"
                  className="form-select"
                  value={form.source}
                  disabled
                  onChange={e => setForm({ ...form, source: e.target.value })}
                >
                  <option value="manual">Manual</option>
                </select>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                  Automated sources (Snort, Wazuh, etc.) are handled via API ingesta.
                </div>
              </div>

              {/* Severity */}
              <div className="form-group">
                <label className="form-label" htmlFor="severity-select">Severity</label>
                <select
                  id="severity-select"
                  className="form-select"
                  value={form.severity}
                  onChange={e => setForm({ ...form, severity: e.target.value })}
                >
                  <option value="unknown">Unknown</option>
                  <option value="critical">🔴 Critical</option>
                  <option value="high">🟠 High</option>
                  <option value="medium">🟡 Medium</option>
                  <option value="low">🟢 Low</option>
                </select>
              </div>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <button 
                type="submit" 
                className="btn btn-primary" 
                disabled={loading || mapping || !form.incident.trim()}
              >
                {loading ? <span className="spinner" /> : <SendHorizonal size={15} />}
                {loading ? 'Queuing…' : 'Full Pipeline Analysis'}
              </button>
              
              <button
                type="button"
                className="btn btn-secondary"
                disabled={loading || mapping || !form.incident.trim()}
                onClick={handleMapTTP}
                style={{ borderColor: 'var(--accent)', color: 'white' }}
              >
                {mapping ? <span className="spinner" /> : <Swords size={15} />}
                {mapping ? 'Analyzing with AI…' : 'AI TTP Mapper (Consulta)'}
              </button>

              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setForm({ ...form, incident: EXAMPLE })}
              >
                Load Example
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => { setForm({ ...form, incident: '' }); setMapResult(null); setMapError(null); }}
              >
                Clear
              </button>
            </div>
          </form>

          {/* TTP Mapper Results View */}
          {(mapping || mapResult || mapError) && (
            <div style={{ marginTop: 32, paddingTop: 32, borderTop: '1px solid var(--border)' }}>
              <div className="analysis-section-title" style={{ color: 'var(--accent)', marginBottom: 20 }}>
                <Swords size={16} /> AI TTP Mapper Results
              </div>

              {mapping && (
                <div className="empty-state" style={{ paddingTop: 20 }}>
                  <div className="spinner" style={{ width: 36, height: 36, margin: '0 auto 16px' }} />
                  <div className="empty-state-title">AI analyzing event…</div>
                  <div className="empty-state-sub">LLM extracting techniques → validating against MITRE database</div>
                </div>
              )}

              {mapError && !mapping && (
                <div className="analysis-section" style={{ borderLeft: '3px solid var(--danger)' }}>
                  <div style={{ color: 'var(--danger)', display: 'flex', gap: 8, alignItems: 'center' }}>
                    <AlertTriangle size={16} /> {mapError}
                  </div>
                </div>
              )}

              {mapResult && !mapping && (
                <div>
                  {mapResult.summary && (
                    <div className="analysis-section" style={{ marginBottom: 16 }}>
                      <div className="analysis-section-title">📋 AI Summary</div>
                      <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>{mapResult.summary}</p>
                    </div>
                  )}

                  {mapResult.validation_stats && (
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
                      {[
                        ['Proposed', mapResult.validation_stats.total_proposed, 'var(--accent)'],
                        ['Valid',    mapResult.validation_stats.valid,          'var(--ok)'],
                        ['Rejected', mapResult.validation_stats.rejected,       'var(--danger)'],
                      ].map(([label, val, color]) => (
                        <div key={label} style={{
                          background: 'var(--bg-card)', border: '1px solid var(--border)',
                          borderRadius: 8, padding: '10px 18px', textAlign: 'center',
                        }}>
                          <div style={{ fontSize: 22, fontWeight: 800, color }}>{val}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="section-title" style={{ marginBottom: 12 }}>
                    {mapResult.techniques?.length > 0
                      ? `${mapResult.techniques.length} Techniques Identified`
                      : 'No Validated Techniques Found'}
                  </div>
                  {mapResult.techniques?.map((tech, i) => (
                    <MappedTechCard key={tech.id || i} tech={tech} idx={i} />
                  ))}
                </div>
              )}
            </div>
          )}

        </div>
      </div>

      {toast && (
        <div className={`toast toast-${toast.type}`}>
          {toast.type === 'ok'
            ? <CheckCircle size={16} color="var(--ok)" />
            : <AlertCircle size={16} color="var(--danger)" />
          }
          {toast.msg}
        </div>
      )}
    </>
  )
}

