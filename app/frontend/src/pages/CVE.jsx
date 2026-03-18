import { useState } from 'react'
import { Search, AlertTriangle, ExternalLink, Shield } from 'lucide-react'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function scoreColor(cvss) {
  if (!cvss) return 'var(--text-muted)'
  if (cvss >= 9.0) return 'var(--danger)'
  if (cvss >= 7.0) return '#fb923c'
  if (cvss >= 4.0) return 'var(--warn)'
  return 'var(--ok)'
}

function scoreLabel(cvss) {
  if (!cvss) return 'N/A'
  if (cvss >= 9.0) return 'CRITICAL'
  if (cvss >= 7.0) return 'HIGH'
  if (cvss >= 4.0) return 'MEDIUM'
  return 'LOW'
}

function CveCard({ cve }) {
  const color = scoreColor(cve.cvss)
  return (
    <div className="analysis-section" style={{ borderLeft: `3px solid ${color}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <span className="cve-id">{cve.id}</span>
            <span style={{
              background: `${color}22`, color, border: `1px solid ${color}66`,
              borderRadius: 20, padding: '2px 10px', fontSize: 10, fontWeight: 700,
            }}>
              {scoreLabel(cve.cvss)}
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
            {cve.description || 'No description available.'}
          </p>
        </div>
        <div style={{ textAlign: 'center', flexShrink: 0 }}>
          <div style={{ fontSize: 28, fontWeight: 800, color, lineHeight: 1 }}>
            {cve.cvss ?? '—'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>CVSS</div>
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
            target="_blank"
            rel="noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--accent)', marginTop: 6 }}
          >
            <ExternalLink size={11} /> NVD
          </a>
        </div>
      </div>
    </div>
  )
}

export default function CVE() {
  const [query,   setQuery]   = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error,   setError]   = useState(null)

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setResults(null)
    setError(null)
    try {
      const res = await fetch(`${BASE}/api/v1/enrichment/cve?q=${encodeURIComponent(query.trim())}`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'NVD API error')
      setResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const EXAMPLES = ['log4j', 'CVE-2024-3400', 'CVE-2023-44487', 'Apache HTTP Server', 'Windows Print Spooler']

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">CVE / Vulnerabilities</div>
          <div className="topbar-sub">Search the NVD database by CVE ID or keyword</div>
        </div>
        <a
          href="https://nvd.nist.gov"
          target="_blank"
          rel="noreferrer"
          className="btn btn-secondary"
        >
          <ExternalLink size={14} /> NVD
        </a>
      </div>

      <div className="page">
        <div className="form-panel">
          <form onSubmit={handleSearch}>
            <div className="form-group">
              <label className="form-label" htmlFor="cve-query">CVE ID or keyword</label>
              <div style={{ display: 'flex', gap: 10 }}>
                <input
                  id="cve-query"
                  className="form-input"
                  placeholder="e.g. log4j  |  CVE-2023-44487  |  Apache"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                />
                <button className="btn btn-primary" type="submit" disabled={loading || !query.trim()}>
                  {loading ? <span className="spinner" /> : <Search size={15} />}
                  {loading ? 'Searching…' : 'Search'}
                </button>
              </div>
            </div>
          </form>

          {/* Quick examples */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 20 }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>Examples:</span>
            {EXAMPLES.map(ex => (
              <button
                key={ex}
                className="btn btn-secondary"
                style={{ fontSize: 11, padding: '4px 10px' }}
                onClick={() => setQuery(ex)}
              >
                {ex}
              </button>
            ))}
          </div>

          {error && (
            <div className="analysis-section" style={{ borderLeft: '3px solid var(--danger)' }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', color: 'var(--danger)' }}>
                <AlertTriangle size={16} /> {error}
              </div>
            </div>
          )}

          {loading && (
            <div className="flex-center" style={{ padding: 60 }}>
              <div className="spinner" style={{ width: 32, height: 32 }} />
            </div>
          )}

          {results && !loading && (
            <>
              <div className="section-header" style={{ marginBottom: 12 }}>
                <div>
                  <div className="section-title">Results for "{results.query}"</div>
                  <div className="section-sub">{results.results.length} vulnerabilities found</div>
                </div>
              </div>
              {results.results.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-state-icon"><Shield size={40} /></div>
                  <div className="empty-state-title">No CVEs found</div>
                  <div className="empty-state-sub">Try a different keyword or check the CVE ID format.</div>
                </div>
              ) : (
                results.results.map(cve => <CveCard key={cve.id} cve={cve} />)
              )}
            </>
          )}
        </div>
      </div>
    </>
  )
}
