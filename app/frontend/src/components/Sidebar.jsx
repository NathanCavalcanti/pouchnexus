import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, ShieldAlert, Plus, BookOpen, Settings, Shield,
  Bug, FileWarning, Swords, HelpCircle
} from 'lucide-react'

const mainNav = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/incidents', icon: ShieldAlert,     label: 'Incidents' },
  { to: '/submit',    icon: Plus,            label: 'New Incident' },
  { to: '/playbooks', icon: BookOpen,        label: 'Playbooks' },
  { to: '/help',      icon: HelpCircle,      label: 'Help' },
]

const enrichNav = [
  { to: '/virustotal', icon: Bug,         label: 'VirusTotal' },
  { to: '/cve',        icon: FileWarning, label: 'CVE / NVD' },
  { to: '/mitre',      icon: Swords,      label: 'MITRE ATT&CK' },
]

function NavItem({ to, icon: Icon, label }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
    >
      <Icon size={16} />
      {label}
    </NavLink>
  )
}

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon"><Shield size={18} color="#fff" /></div>
        <div className="logo-text">
          SOC Platform
          <span>Multi-Agent AI</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Operations</div>
        {mainNav.map(item => <NavItem key={item.to} {...item} />)}

        <div className="nav-section-label" style={{ marginTop: 14 }}>Enrichment &amp; Intel</div>
        {enrichNav.map(item => <NavItem key={item.to} {...item} />)}

        <div className="nav-section-label" style={{ marginTop: 14 }}>System</div>
        <NavItem to="/settings" icon={Settings} label="Settings" />
      </nav>

      <div className="sidebar-footer">
        <div className="status-badge-online">
          <span className="status-dot" />
          Engine Online
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
          v2.0 · LangGraph
        </div>
      </div>
    </aside>
  )
}
