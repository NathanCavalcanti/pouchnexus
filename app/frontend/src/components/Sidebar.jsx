import { NavLink } from 'react-router-dom'
import { ShieldAlert, Plus, BookOpen, Settings, Shield, Bug, FileWarning, Swords, HelpCircle, LayoutDashboard, X } from 'lucide-react'
import { useApp } from '../context/AppContext'

function NavItem({ to, icon: Icon, label, onClick }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
      onClick={onClick}
    >
      <Icon size={16} />
      {label}
    </NavLink>
  )
}

export default function Sidebar({ isOpen, onClose }) {
  const { t } = useApp()

  const mainNav = [
    { to: '/dashboard', icon: LayoutDashboard, label: t.dashboard },
    { to: '/incidents', icon: ShieldAlert,     label: t.incidents },
    { to: '/submit',    icon: Plus,            label: t.new_incident },
    { to: '/playbooks', icon: BookOpen,        label: t.playbooks },
    { to: '/help',      icon: HelpCircle,      label: t.help },
  ]

  const enrichNav = [
    { to: '/virustotal', icon: Bug,         label: t.virustotal },
    { to: '/cve',        icon: FileWarning, label: t.cve_nvd },
    { to: '/mitre',      icon: Swords,      label: t.mitre_attack },
  ]

  return (
    <aside className={`sidebar ${isOpen ? 'open' : ''}`}>
      <div className="sidebar-logo">
        <div className="logo-icon"><Shield size={20} color="#fff" /></div>
        <div className="logo-text">
          PouchNexus
          <span>SOC Multi-Agent platform</span>
        </div>
        <button className="btn btn-ghost mobile-only" onClick={onClose} style={{ marginLeft: 'auto', display: 'none' }}>
           <X size={20} />
        </button>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Operations</div>
        {mainNav.map(item => <NavItem key={item.to} {...item} onClick={onClose} />)}

        <div className="nav-section-label" style={{ marginTop: 14 }}>Enrichment &amp; Intel</div>
        {enrichNav.map(item => <NavItem key={item.to} {...item} onClick={onClose} />)}

        <div className="nav-section-label" style={{ marginTop: 14 }}>System</div>
        <NavItem to="/settings" icon={Settings} label={t.settings} onClick={onClose} />
      </nav>

      <div className="sidebar-footer">
        <div className="status-badge-online">
          <span className="status-dot" />
          Engine Online
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
          v3.2 · PouchNexus Edition
        </div>
      </div>
    </aside>
  )
}
