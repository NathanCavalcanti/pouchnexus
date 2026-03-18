import { useState, useEffect } from 'react'
import { Save, Eye, EyeOff, CheckCircle } from 'lucide-react'
import { api } from '../api.js'

function Field({ id, label, value, onChange, type = 'text', placeholder = '', hint }) {
  const [show, setShow] = useState(false)
  const isSecret = type === 'password'

  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>{label}</label>
      <div style={{ position: 'relative' }}>
        <input
          id={id}
          type={isSecret && !show ? 'password' : 'text'}
          className="form-input"
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          style={isSecret ? { paddingRight: 40 } : {}}
        />
        {isSecret && (
          <button
            type="button"
            onClick={() => setShow(s => !s)}
            style={{
              position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)',
            }}
          >
            {show ? <EyeOff size={15} /> : <Eye size={15} />}
          </button>
        )}
      </div>
      {hint && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{hint}</div>}
    </div>
  )
}

export default function Settings() {
  const [saved, setSaved] = useState(false)
  const [apiStatus, setApiStatus] = useState(null)
  const [clickCount, setClickCount] = useState(0)

  const [keys, setKeys] = useState({
    groq: '',
    gemini: '',
    nvd: '',
    virustotal: '',
    debug_logging: false,
  })

  // Load saved keys from backend on mount
  useEffect(() => {
    api.getKeys()
      .then(res => setKeys(res))
      .catch(err => console.error("Failed to load keys:", err))
  }, [])

  useEffect(() => {
    api.health()
      .then(r => setApiStatus(r.status))
      .catch(() => setApiStatus('offline'))
  }, [])

  const handleSave = async () => {
    try {
      await api.updateKeys(keys)
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (err) {
      alert("Failed to save keys: " + err.message)
    }
  }

  const set = (field) => (val) => setKeys(k => ({ ...k, [field]: val }))

  return (
    <>
      <div className="topbar">
        <div>
          <div 
            className="topbar-title" 
            onClick={() => setClickCount(c => (c + 1) % 10)}
            style={{ cursor: 'pointer', userSelect: 'none' }}
          >
            Settings
          </div>
          <div className="topbar-sub">Platform configuration and API key management</div>
        </div>
      </div>

      <div className="page">
        {/* API Status */}
        <div className="settings-section" style={{ marginBottom: 20 }}>
          <div className="settings-section-title">🔌 Backend Status</div>
          <div style={{ display: 'flex', gap: 20 }}>
            <div>
              <div className="text-sm text-muted">API Server</div>
              <div style={{ fontSize: 14, fontWeight: 600, marginTop: 4 }}>
                {apiStatus === null ? (
                  <span><span className="spinner" style={{ width: 12, height: 12 }} /></span>
                ) : apiStatus === 'healthy' ? (
                  <span style={{ color: 'var(--ok)' }}>● Online</span>
                ) : (
                  <span style={{ color: 'var(--danger)' }}>● {apiStatus}</span>
                )}
              </div>
              <div className="text-xs text-muted" style={{ marginTop: 2 }}>http://localhost:8000</div>
            </div>
            <div>
              <div className="text-sm text-muted">Swagger UI</div>
              <a
                href="http://localhost:8000/api/docs"
                target="_blank"
                rel="noreferrer"
                style={{ color: 'var(--accent)', fontSize: 14, fontWeight: 600, display: 'block', marginTop: 4 }}
              >
                Open API Docs →
              </a>
            </div>
          </div>
        </div>

        {/* API Keys */}
        <div className="settings-section">
          <div className="settings-section-title">🔑 API Keys</div>
          <p className="text-sm text-muted mb-16">
            These keys are saved directly to your <code style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>.env</code> file. The backend will automatically reload when you save them.
          </p>

          <Field
            id="groq-key"
            label="Groq API Key (Primary LLM)"
            value={keys.groq}
            onChange={set('groq')}
            type="password"
            placeholder="gsk_..."
            hint="Required · Free tier at console.groq.com"
          />
          <Field
            id="gemini-key"
            label="Gemini API Key (Fallback LLM)"
            value={keys.gemini}
            onChange={set('gemini')}
            type="password"
            placeholder="AIzaSy..."
            hint="Optional · aistudio.google.com"
          />
          <Field
            id="nvd-key"
            label="NVD API Key"
            value={keys.nvd}
            onChange={set('nvd')}
            type="password"
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            hint="Optional · Increases CVE rate limits · nvd.nist.gov"
          />
          <Field
            id="vt-key"
            label="VirusTotal API Key"
            value={keys.virustotal}
            onChange={set('virustotal')}
            type="password"
            placeholder="64-char key"
            hint="Optional · Enables hash/IP/URL/domain enrichment"
          />

          {(clickCount >= 5 || keys.debug_logging) && (
            <div style={{ padding: '15px', background: 'var(--bg-lighter)', borderRadius: 8, border: '1px solid var(--border)', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--danger)', fontSize: 13 }}>⚠️ Developer Debug Mode</div>
                  <div className="text-xs text-muted">Saves all LLM API requests and raw responses to the /logs directory. Uncheck passing when in production.</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input 
                    type="checkbox" 
                    checked={keys.debug_logging} 
                    onChange={e => set('debug_logging')(e.target.checked)} 
                    style={{ marginRight: 8 }}
                  />
                  Enable Verbose Logging
                </label>
              </div>
            </div>
          )}

          <button className="btn btn-primary" onClick={handleSave}>
            {saved ? <CheckCircle size={15} /> : <Save size={15} />}
            {saved ? 'Saved to .env!' : 'Save Keys'}
          </button>
        </div>

        {/* Webhook Reference */}
        <div className="settings-section">
          <div className="settings-section-title">🔗 Webhook Ingestion URLs</div>
          <p className="text-sm text-muted mb-16">
            Configure your security tools to POST to these endpoints. The platform will automatically
            analyze the alerts in the background.
          </p>
          {[
            { src: 'Snort / Suricata', url: 'http://localhost:8000/api/v1/ingest/snort',   hint: 'JSON alert format with alert, src_ip, dest_ip fields' },
            { src: 'Wazuh',            url: 'http://localhost:8000/api/v1/ingest/wazuh',   hint: 'Standard Wazuh alert JSON (rule, agent, full_log fields)' },
            { src: 'n8n / Generic',    url: 'http://localhost:8000/api/v1/ingest/generic', hint: 'Flexible: any JSON with text, log, or alert field' },
            { src: 'Manual',           url: 'http://localhost:8000/api/v1/analyze',         hint: 'POST {"incident": "..."} for one-off manual analysis' },
          ].map(({ src, url, hint }) => (
            <div key={url} style={{ marginBottom: 14 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{src}</div>
              <div className="mono" style={{ color:'var(--accent)', fontSize: 12, margin: '3px 0' }}>POST {url}</div>
              <div className="text-xs text-muted">{hint}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
