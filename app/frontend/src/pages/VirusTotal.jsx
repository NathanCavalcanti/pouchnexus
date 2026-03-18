import { useState } from 'react'
import { Search, ExternalLink, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import { api } from '../api.js'

// ── API helpers ────────────────────────────────────────────────────────────
const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function vtQuery(type, value) {
  if (type === 'url') {
    const res = await fetch(`${BASE}/api/v1/enrichment/virustotal/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: value }),
    })
    return res.json()
  }
  const res = await fetch(`${BASE}/api/v1/enrichment/virustotal/${type}/${encodeURIComponent(value)}`)
  return res.json()
}

// ── Score ring ────────────────────────────────────────────────────────────
function ScoreRing({ malicious, total }) {
  const pct = total > 0 ? Math.round((malicious / total) * 100) : 0
  const color = malicious === 0 ? 'var(--ok)' : malicious < 5 ? 'var(--warn)' : 'var(--danger)'
  return (
    <div style={{ textAlign: 'center' }}>
      <svg width="90" height="90" viewBox="0 0 90 90">
        <circle cx="45" cy="45" r="38" fill="none" stroke="var(--bg-card)" strokeWidth="8" />
        <circle
          cx="45" cy="45" r="38"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={`${2 * Math.PI * 38}`}
          strokeDashoffset={`${2 * Math.PI * 38 * (1 - pct / 100)}`}
          strokeLinecap="round"
          transform="rotate(-90 45 45)"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text x="45" y="48" textAnchor="middle" fill={color} fontSize="14" fontWeight="700" fontFamily="Inter">
          {malicious}/{total}
        </text>
        <text x="45" y="62" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter">
          engines
        </text>
      </svg>
      <div style={{ fontSize: 12, marginTop: 4, color }}>
        {malicious === 0 ? '✅ Clean' : malicious < 5 ? '⚠️ Suspicious' : '🔴 Malicious'}
      </div>
    </div>
  )
}

// ── Result card ───────────────────────────────────────────────────────────
function ResultCard({ data, iocType, value }) {
  if (data.error) {
    return (
      <div className="analysis-section">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--danger)' }}>
          <AlertTriangle size={16} />
          <span>{data.error}</span>
        </div>
      </div>
    )
  }

  const rows = []
  if (data.reputation !== undefined) rows.push(['Reputation Score', data.reputation])
  if (data.country)    rows.push(['Country',   data.country])
  if (data.asn)        rows.push(['ASN',        data.asn])
  if (data.as_owner)   rows.push(['Owner/ISP',  data.as_owner])
  if (data.registrar)  rows.push(['Registrar',  data.registrar])
  if (data.threat_label && data.threat_label !== '') rows.push(['Threat Label', data.threat_label])
  if (data.names?.length)            rows.push(['File Names',      data.names.join(', ')])
  if (data.sandbox_verdicts?.length) rows.push(['Sandbox Verdict', data.sandbox_verdicts.join(', ')])
  if (data.sigma_rules?.length)      rows.push(['Sigma Rules',     data.sigma_rules.join(', ')])
  if (data.categories?.length)       rows.push(['Categories',      Array.isArray(data.categories) ? data.categories.join(', ') : Object.values(data.categories).join(', ')])

  return (
    <div className="analysis-section">
      <div className="analysis-section-title">🔍 VirusTotal Result — <span className="mono">{value}</span></div>
      <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <ScoreRing malicious={data.malicious_count ?? 0} total={data.total_engines ?? 0} />
        <div style={{ flex: 1, minWidth: 240 }}>
          {rows.map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span className="text-muted">{k}</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, textAlign: 'right', maxWidth: 260, wordBreak: 'break-all' }}>{String(v)}</span>
            </div>
          ))}
          {data.permalink && (
            <a
              href={data.permalink}
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ marginTop: 12, fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              <ExternalLink size={13} /> Open in VirusTotal
            </a>
          )}
        </div>
      </div>
    </div>
  )
}

// ── IOC type detector ─────────────────────────────────────────────────────
function detectType(value) {
  const v = value.trim()
  if (/^https?:\/\//i.test(v)) return 'url'
  if (/^[0-9a-f]{32}$/i.test(v)) return 'hash'    // MD5
  if (/^[0-9a-f]{40}$/i.test(v)) return 'hash'    // SHA1
  if (/^[0-9a-f]{64}$/i.test(v)) return 'hash'    // SHA256
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip'
  return 'domain'
}

const TYPE_LABELS = { hash: 'File Hash', ip: 'IP Address', domain: 'Domain', url: 'URL' }

export default function VirusTotal() {
  const [query,   setQuery]   = useState('')
  const [iocType, setIocType] = useState('hash')
  const [loading, setLoading] = useState(false)
  const [result,  setResult]  = useState(null)

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const detected = detectType(query)
      setIocType(detected)
      const data = await vtQuery(detected, query.trim())
      setResult({ data, iocType: detected, value: query.trim() })
    } catch (err) {
      setResult({ data: { error: err.message }, iocType, value: query.trim() })
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">VirusTotal</div>
          <div className="topbar-sub">Hash · IP · Domain · URL reputation lookup</div>
        </div>
        <a
          href="https://www.virustotal.com"
          target="_blank"
          rel="noreferrer"
          className="btn btn-secondary"
        >
          <ExternalLink size={14} /> Open VT
        </a>
      </div>

      <div className="page">
        <div className="form-panel">
          {/* Search */}
          <form onSubmit={handleSearch}>
            <div className="form-group">
              <label className="form-label" htmlFor="vt-query">
                IOC to look up — auto-detected (hash, IP, domain, or URL)
              </label>
              <div style={{ display: 'flex', gap: 10 }}>
                <input
                  id="vt-query"
                  className="form-input"
                  placeholder="e.g. 185.220.101.47  |  malicious.ru  |  d41d8cd98f00b204e9800998ecf8427e"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                />
                <button className="btn btn-primary" type="submit" disabled={loading || !query.trim()}>
                  {loading ? <span className="spinner" /> : <Search size={15} />}
                  {loading ? 'Querying…' : 'Search'}
                </button>
              </div>
            </div>
          </form>


          {/* Result */}
          {result && (
            <ResultCard data={result.data} iocType={result.iocType} value={result.value} />
          )}
        </div>
      </div>
    </>
  )
}
