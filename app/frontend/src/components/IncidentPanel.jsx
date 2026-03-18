import { useEffect, useRef } from 'react'
import { X, AlertTriangle, Network, FileSearch, Swords, FileText, Tag, ShieldAlert, ExternalLink } from 'lucide-react'

function StatusBadge({ status }) {
  return <span className={`badge badge-${status ?? 'unknown'}`}>{status ?? 'unknown'}</span>
}

function SevLabel({ sev }) {
  return <span className={`sev-${sev ?? 'unknown'}`}>{(sev ?? 'unknown').toUpperCase()}</span>
}

function IocList({ label, items }) {
  if (!items?.length) return null
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
        {label}
      </div>
      <div className="ioc-list">
        {items.map((v, i) => (
          <span key={i} className="ioc-tag">{v}</span>
        ))}
      </div>
    </div>
  )
}

// ── VirusTotal Card Components ───────────────────────────────────────────

function VTRatio({ malicious, total }) {
  const isDanger = malicious > 0
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      background: isDanger ? 'var(--danger-bg)' : 'var(--ok-bg)',
      color: isDanger ? 'var(--danger)' : 'var(--ok)',
      padding: '2px 8px', borderRadius: 12, fontSize: 11, fontWeight: 700,
      border: `1px solid ${isDanger ? 'var(--danger)' : 'var(--ok)'}44`
    }}>
      <ShieldAlert size={12} />
      {malicious} / {total}
    </div>
  )
}

function VTMetaItem({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 4 }}>
      <span style={{ color: 'var(--text-muted)' }}>{label}:</span>
      <span style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  )
}

export default function IncidentPanel({ incident, onClose }) {
  const overlayRef = useRef(null)

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  const iocs = incident.iocs || {}
  const ttps = incident.ttps || {}
  const cves = incident.cves || {}
  const plan = incident.investigation_plan || {}

  const techniques = ttps.techniques || ttps.matched_techniques || []
  const cveList    = cves.cves || cves.vulnerabilities || []
  const threats    = plan.threats || plan.immediate_actions || []
  const contains   = plan.containment || plan.containment_steps || []
  const evidence   = plan.evidence || plan.collect_evidence || []

  // VT Data
  const vtHashes  = iocs.virustotal_results || []
  const vtIps     = iocs.virustotal_ip_results || []
  const vtUrls    = iocs.virustotal_url_results || []
  const vtDomains = iocs.virustotal_domain_results || []
  const hasVtData = vtHashes.length > 0 || vtIps.length > 0 || vtUrls.length > 0 || vtDomains.length > 0

  return (
    <div
      className="modal-overlay"
      ref={overlayRef}
      onClick={(e) => { if (e.target === overlayRef.current) onClose() }}
    >
      <div className="slide-panel">
        {/* Header */}
        <div className="panel-header">
          <div>
            <div className="panel-title">
              <ShieldIcon /> Incident Report
            </div>
            <div className="panel-meta">
              ID: {incident.id} · Source: {incident.source} · <StatusBadge status={incident.status} />
            </div>
            <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
              Created: {new Date(incident.created_at).toLocaleString()} ·
              Severity: <SevLabel sev={incident.severity} />
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose} style={{ padding: '6px' }}>
            <X size={18} />
          </button>
        </div>

        {incident.status === 'pending' || incident.status === 'analyzing' ? (
          <div className="empty-state">
            <div className="spinner" style={{ width: 36, height: 36, margin: '0 auto 16px' }} />
            <div className="empty-state-title">Analysis in progress…</div>
            <div className="empty-state-sub">LangGraph agents are working on it. Refresh in a moment.</div>
          </div>
        ) : incident.status === 'failed' ? (
          <div className="analysis-section">
            <div className="analysis-section-title"><AlertTriangle size={14} /> Error</div>
            <p className="text-sm text-danger">{incident.error || 'Unknown error during analysis.'}</p>
          </div>
        ) : (
          <>
            {/* Raw Log */}
            <div className="analysis-section">
              <div className="analysis-section-title"><FileSearch size={13} /> Raw Log / Input</div>
              <div className="report-text" style={{ maxHeight: 140 }}>{incident.raw_text}</div>
            </div>

            {/* IOCs */}
            {iocs && Object.keys(iocs).length > 0 && (
              <div className="analysis-section">
                <div className="analysis-section-title"><Network size={13} /> Indicators of Compromise (IOCs)</div>
                <IocList label="IPs"        items={iocs.ips} />
                <IocList label="Domains"    items={iocs.domains} />
                <IocList label="URLs"       items={iocs.urls} />
                <IocList label="Emails"     items={iocs.emails} />
                <IocList label="File Paths" items={iocs.file_paths} />
                {iocs.hashes && (
                  <>
                    <IocList label="MD5"    items={iocs.hashes.md5} />
                    <IocList label="SHA1"   items={iocs.hashes.sha1} />
                    <IocList label="SHA256" items={iocs.hashes.sha256} />
                  </>
                )}
              </div>
            )}

            {/* ERROR: AI sometimes hallucinates 'virustotal_results' so we conditionally render the dedicated VT section */}
            {hasVtData && (
              <div className="analysis-section">
                <div className="analysis-section-title" style={{ color: '#3b82f6', borderBottom: '1px solid #3b82f644', paddingBottom: 8, marginBottom: 12 }}>
                  <ShieldAlert size={14} /> VirusTotal Validations
                </div>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {vtHashes.map((r, i) => (
                    <div key={`h-${i}`} className="cve-item" style={{ borderLeftColor: r.malicious > 0 ? 'var(--danger)' : 'var(--ok)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                             <span className="badge" style={{ fontSize: 9 }}>HASH</span>
                             <span className="mono" style={{ fontSize: 12, color: 'var(--text-primary)' }}>{r.hash}</span>
                          </div>
                          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                             <VTRatio malicious={r.malicious} total={r.total} />
                             <VTMetaItem label="Threat" value={r.threat_label} />
                          </div>
                          {r.names && r.names.length > 0 && (
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                              aka: {r.names.slice(0,3).join(', ')}
                            </div>
                          )}
                        </div>
                        {r.permalink && (
                          <a href={r.permalink} target="_blank" rel="noreferrer" className="btn btn-ghost" style={{ padding: 4 }}>
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}

                  {vtIps.map((r, i) => (
                    <div key={`ip-${i}`} className="cve-item" style={{ borderLeftColor: r.malicious > 0 ? 'var(--danger)' : 'var(--ok)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                             <span className="badge" style={{ fontSize: 9 }}>IP</span>
                             <span className="mono" style={{ fontSize: 12, color: 'var(--text-primary)' }}>{r.ip}</span>
                          </div>
                          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                             <VTRatio malicious={r.malicious} total={r.total} />
                             <VTMetaItem label="Reputation" value={r.reputation} />
                             <VTMetaItem label="Country" value={r.country} />
                             <VTMetaItem label="Owner" value={r.as_owner} />
                          </div>
                        </div>
                        {r.permalink && (
                          <a href={r.permalink} target="_blank" rel="noreferrer" className="btn btn-ghost" style={{ padding: 4 }}>
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}

                  {vtUrls.map((r, i) => (
                    <div key={`u-${i}`} className="cve-item" style={{ borderLeftColor: r.malicious > 0 ? 'var(--danger)' : 'var(--ok)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div style={{ maxWidth: '85%' }}>
                          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                             <span className="badge" style={{ fontSize: 9 }}>URL</span>
                             <span className="mono truncate" style={{ fontSize: 12, color: 'var(--text-primary)', display: 'block' }}>{r.url}</span>
                          </div>
                          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                             <VTRatio malicious={r.malicious} total={r.total} />
                          </div>
                        </div>
                        {r.permalink && (
                          <a href={r.permalink} target="_blank" rel="noreferrer" className="btn btn-ghost" style={{ padding: 4 }}>
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}

                  {vtDomains.map((r, i) => (
                    <div key={`d-${i}`} className="cve-item" style={{ borderLeftColor: r.malicious > 0 ? 'var(--danger)' : 'var(--ok)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                             <span className="badge" style={{ fontSize: 9 }}>DOMAIN</span>
                             <span className="mono" style={{ fontSize: 12, color: 'var(--text-primary)' }}>{r.domain}</span>
                          </div>
                          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                             <VTRatio malicious={r.malicious} total={r.total} />
                             {r.categories && r.categories.length > 0 && (
                               <VTMetaItem label="Categories" value={r.categories.join(', ')} />
                             )}
                          </div>
                        </div>
                        {r.permalink && (
                          <a href={r.permalink} target="_blank" rel="noreferrer" className="btn btn-ghost" style={{ padding: 4 }}>
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE */}
            {techniques.length > 0 && (
              <div className="analysis-section">
                <div className="analysis-section-title"><Swords size={13} /> MITRE ATT&amp;CK Techniques</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {techniques.map((t, i) => {
                    const id   = t.technique_id || t.id || ''
                    const name = t.technique_name || t.name || t
                    return (
                      <span key={i} className="mitre-badge">
                        {id && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>{id}</span>}
                        {name}
                      </span>
                    )
                  })}
                </div>
              </div>
            )}

            {/* CVEs */}
            {cveList.length > 0 && (
              <div className="analysis-section">
                <div className="analysis-section-title"><Tag size={13} /> CVEs / Vulnerabilities</div>
                {cveList.map((c, i) => (
                  <div key={i} className="cve-item">
                    <div className="cve-id">{c.cve_id || c.id}</div>
                    <div className="cve-desc">{c.description || c.summary || ''}</div>
                    {c.cvss_score && (
                      <div style={{ marginTop: 4, fontSize: 11, color: 'var(--warn)' }}>
                        CVSS: {c.cvss_score}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Investigation Plan */}
            {(threats.length > 0 || contains.length > 0 || evidence.length > 0) && (
              <div className="analysis-section">
                <div className="analysis-section-title"><AlertTriangle size={13} /> Investigation Plan</div>
                {threats.length > 0 && (
                  <PlanList title="Immediate Actions" items={threats} color="var(--danger)" />
                )}
                {contains.length > 0 && (
                  <PlanList title="Containment Steps" items={contains} color="var(--warn)" />
                )}
                {evidence.length > 0 && (
                  <PlanList title="Evidence to Collect" items={evidence} color="var(--info)" />
                )}
              </div>
            )}

            {/* Full Report Text */}
            {incident.report_text && (
              <div className="analysis-section">
                <div className="analysis-section-title"><FileText size={13} /> Full SOC Report</div>
                <div className="report-text">{incident.report_text}</div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function ShieldIcon() {
  return <span style={{ marginRight: 6, opacity: 0.7 }}>🛡️</span>
}

function PlanList({ title, items, color }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 12, fontWeight: 700, color, marginBottom: 6 }}>{title}</div>
      {items.map((item, i) => (
        <div key={i} style={{
          fontSize: 12,
          color: 'var(--text-secondary)',
          padding: '4px 0 4px 12px',
          borderLeft: `2px solid ${color}`,
          marginBottom: 4,
        }}>
          {typeof item === 'string' ? item : JSON.stringify(item)}
        </div>
      ))}
    </div>
  )
}
