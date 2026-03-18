import { HelpCircle, Info, Zap, Link, ShieldAlert, Cpu, Terminal } from 'lucide-react'

export default function Help() {
  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Help & Documentation</div>
          <div className="topbar-sub">System guides, webhook documentation, and integration tips</div>
        </div>
      </div>

      <div className="page" style={{ maxWidth: 800 }}>
        
        {/* Pipeline Info */}
        <div className="analysis-section">
          <div className="analysis-section-title">
            <Zap size={15} style={{ color: 'var(--warn)' }} /> 
            How Full Pipeline Analysis works
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <p>The Full Pipeline is a multi-agent orchestration that processes raw security data using specialized AI units:</p>
            <ol style={{ paddingLeft: 20, marginTop: 12 }}>
              <li><strong>IOC Agent:</strong> Extracts hashes, IPs, domains and URLs.</li>
              <li><strong>Enrichment Node:</strong> Queries VirusTotal for file reputation.</li>
              <li><strong>MITRE Agent:</strong> Maps behavior to TTPs using local validated database.</li>
              <li><strong>CVE Agent:</strong> Fetches vulnerability data from NVD API.</li>
              <li><strong>Investigation Agent:</strong> Designs DFIR containment and action plans.</li>
              <li><strong>Report Agent:</strong> Compiles the final executive and technical summary.</li>
            </ol>
            <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: 'var(--bg-card-hover)', border: '1px solid var(--border)' }}>
              <Info size={14} style={{ marginRight: 6, color: 'var(--accent)' }} />
              <strong>Note:</strong> Analysis is asynchronous. You can leave the page and check progress later in the <strong>Incidents</strong> tab.
            </div>
          </div>
        </div>

        {/* Webhooks Info */}
        <div className="analysis-section" style={{ marginTop: 24 }}>
          <div className="analysis-section-title">
            <Link size={15} style={{ color: 'var(--ok)' }} /> 
            Ingestion Webhooks
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <p>Connect your security infrastructure using these endpoints. All respond with <code>202 Accepted</code>.</p>
            
            <div style={{ marginTop: 16 }}>
              {[
                { name: 'Snort / Suricata', url: '/api/v1/ingest/snort', desc: 'Accepts standard Snort JSON alert format.' },
                { name: 'Wazuh', url: '/api/v1/ingest/wazuh', desc: 'Requires custom integration in Wazuh Manager to POST alerts.' },
                { name: 'Generic / Honeypot', url: '/api/v1/ingest/generic', desc: 'Flexible endpoint. Accepts any JSON with a text, log, or alert field.' },
              ].map(w => (
                <div key={w.url} style={{ padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{w.name}</strong>
                    <code className="mono" style={{ color: 'var(--accent)', background: 'var(--bg-base)', padding: '2px 6px', borderRadius: 4 }}>{w.url}</code>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{w.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* API Requirements */}
        <div className="analysis-section" style={{ marginTop: 24 }}>
          <div className="analysis-section-title">
            <ShieldAlert size={15} style={{ color: 'var(--danger)' }} /> 
            External API Requirements
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <p>Some features require external API keys configured in your <code>.env</code> file or the <strong>Settings</strong> page:</p>
            <ul style={{ paddingLeft: 20, marginTop: 12 }}>
              <li>
                <strong>VirusTotal:</strong> Required for the VirusTotal tab and automated hash enrichment. 
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>⚠️ URL scans may take ~10s due to VT processing time.</div>
              </li>
              <li><strong>Gemini / Groq:</strong> Required for all AI agent operations.</li>
              <li><strong>NVD:</strong> Optional but recommended for higher CVE lookup rate limits.</li>
            </ul>
          </div>
        </div>

        {/* Debug Mode */}
        <div className="analysis-section" style={{ marginTop: 24 }}>
          <div className="analysis-section-title">
            <Terminal size={15} style={{ color: 'var(--accent)' }} /> 
            Debug & Verbose Logging
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <p>Enable <strong>Debug Logging</strong> in Settings to see raw LLM prompts and API JSON responses in the <code>/logs</code> directory of the server.</p>
          </div>
        </div>

      </div>
    </>
  )
}
