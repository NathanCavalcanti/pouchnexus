import { useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AppProvider } from './context/AppContext.jsx'
import Sidebar from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Incidents from './pages/Incidents.jsx'
import SubmitIncident from './pages/SubmitIncident.jsx'
import Playbooks from './pages/Playbooks.jsx'
import Settings from './pages/Settings.jsx'
import VirusTotal from './pages/VirusTotal.jsx'
import CVE from './pages/CVE.jsx'
import Mitre from './pages/Mitre.jsx'
import Help from './pages/Help.jsx'

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <AppProvider>
      <div className="app-shell">
        <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <div className="main-content">
          <button 
            className="mobile-menu-toggle"
            onClick={() => setSidebarOpen(true)}
            style={{ 
              display: 'none', 
              position: 'fixed', 
              bottom: '24px', 
              right: '24px', 
              zIndex: 101,
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: 'var(--accent)',
              border: 'none',
              color: 'white',
              boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
              cursor: 'pointer'
            }}
          >
            <MenuIcon />
          </button>
          <Routes>
            <Route path="/"             element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard"    element={<Dashboard />} />
            <Route path="/incidents"    element={<Incidents />} />
            <Route path="/submit"       element={<SubmitIncident />} />
            <Route path="/playbooks"    element={<Playbooks />} />
            <Route path="/settings"     element={<Settings />} />
            <Route path="/virustotal"   element={<VirusTotal />} />
            <Route path="/cve"          element={<CVE />} />
            <Route path="/mitre"        element={<Mitre />} />
            <Route path="/help"         element={<Help />} />
          </Routes>
        </div>
      </div>
    </AppProvider>
  )
}

function MenuIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="3" y1="12" x2="21" y2="12"></line>
      <line x1="3" y1="6" x2="21" y2="6"></line>
      <line x1="3" y1="18" x2="21" y2="18"></line>
    </svg>
  )
}
