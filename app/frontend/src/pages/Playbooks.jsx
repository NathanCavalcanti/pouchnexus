const PLAYBOOKS = [
  {
    id: 'pb-001',
    title: '🔴 Ransomware Response',
    desc: 'Immediate containment and response actions for a ransomware infection event.',
    severity: 'critical',
    steps: [
      'Isolate affected hosts from network immediately',
      'Identify patient-zero via EDR telemetry',
      'Block C2 IPs/domains on perimeter firewall',
      'Preserve volatile memory from affected hosts',
      'Notify legal, management, and CISO',
      'Begin recovery from last known-good backup',
      'Submit samples to VirusTotal & MISP',
    ],
  },
  {
    id: 'pb-002',
    title: '🟠 Lateral Movement Detection',
    desc: 'Response when pass-the-hash or pass-the-ticket lateral movement is detected.',
    severity: 'high',
    steps: [
      'Capture Kerberos ticket and NTLM hashes in memory',
      'Identify compromised accounts via SIEM pivot',
      'Force password reset and invalidate tickets (klist purge)',
      'Enable enhanced Kerberos logging (Event 4769/4768)',
      'Audit privileged group membership changes',
      'Review BloodHound / AD CS attack paths',
    ],
  },
  {
    id: 'pb-003',
    title: '🟡 Suspicious PowerShell',
    desc: 'Triage and investigate encoded or obfuscated PowerShell execution.',
    severity: 'medium',
    steps: [
      'Decode base64 payload (PowerShell -enc flag)',
      'Extract IOCs from decoded script',
      'Check script hash against VirusTotal',
      'Review parent process tree (who launched powershell.exe?)',
      'Check persistence locations: registry run keys, scheduled tasks',
      'Block execution via AppLocker / WDAC if confirmed malicious',
    ],
  },
  {
    id: 'pb-004',
    title: '🟡 Phishing / Malicious Email',
    desc: 'Response procedure for reported phishing or malware delivery via email.',
    severity: 'medium',
    steps: [
      'Extract email headers and analyze SPF/DKIM/DMARC',
      'Submit attachments and URLs to VirusTotal',
      'Quarantine email across all mailboxes (M365/Exchange admin)',
      'Block sender domain in email gateway',
      'Check if user clicked links (proxy / DNS logs)',
      'Reset user credentials if compromise suspected',
    ],
  },
  {
    id: 'pb-005',
    title: '🟢 IOC Enrichment Workflow',
    desc: 'Standard procedure to enrich and validate indicators of compromise.',
    severity: 'low',
    steps: [
      'Classify IOC type (IP, domain, hash, URL)',
      'Query VirusTotal API for reputation score',
      'Check abuse.ch, AlienVault OTX, Shodan',
      'Cross-reference against internal threat intel',
      'Create MISP event if IOC is confirmed malicious',
      'Update firewall / EDR block lists',
    ],
  },
  {
    id: 'pb-006',
    title: '🔵 Webhook Integration Setup',
    desc: 'Configure external systems to auto-ingest alerts into this platform.',
    severity: 'info',
    steps: [
      'Start the SOC Platform API (Docker or uvicorn)',
      'For Snort: POST alerts to /api/v1/ingest/snort',
      'For Wazuh: Add custom integration in ossec.conf pointing to /api/v1/ingest/wazuh',
      'For n8n: Use HTTP Request node → POST /api/v1/ingest/generic',
      'Verify ingestion via /api/docs (Swagger UI)',
      'Monitor Dashboard for incoming incidents',
    ],
  },
]

function SevDot({ sev }) {
  const colors = { critical:'var(--danger)', high:'#fb923c', medium:'var(--warn)', low:'var(--ok)', info:'var(--info)' }
  return (
    <span style={{
      display: 'inline-block',
      width: 8, height: 8,
      borderRadius: '50%',
      background: colors[sev] || 'var(--text-muted)',
      marginRight: 6,
      boxShadow: `0 0 6px ${colors[sev] || 'transparent'}`,
    }} />
  )
}

export default function Playbooks() {
  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Playbooks</div>
          <div className="topbar-sub">Standard response procedures for common security incidents</div>
        </div>
      </div>

      <div className="page">
        <div className="playbook-grid">
          {PLAYBOOKS.map(pb => (
            <div key={pb.id} className="playbook-card">
              <div className="playbook-title">
                <SevDot sev={pb.severity} />
                {pb.title}
              </div>
              <div className="playbook-desc">{pb.desc}</div>
              <ol className="playbook-steps">
                {pb.steps.map((step, i) => (
                  <li key={i}>
                    <span className="step-num">{i + 1}</span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
