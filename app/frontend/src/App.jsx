import { Routes, Route, Navigate } from 'react-router-dom'
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
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-content">
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
  )
}
