import { useEffect, useState, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { RefreshCw, Filter, Trash2 } from 'lucide-react'
import { api } from '../api.js'
import IncidentPanel from '../components/IncidentPanel.jsx'

const SOURCES  = ['all', 'manual', 'snort', 'wazuh', 'generic_webhook', 'n8n']
const STATUSES = ['all', 'pending', 'analyzing', 'completed', 'failed']
const ATTACK_TYPES = ['all', 'Network Scan', 'Unauthorized Access', 'Network IDS', 'Endpoint Alert', 'Log Analysis', 'Phishing', 'Malware']

export default function Incidents() {
  const location = useLocation()
  const [incidents, setIncidents] = useState([])
  const [loading,   setLoading]   = useState(true)
  const [selected,  setSelected]  = useState(null)   // full incident object
  const [srcFilter, setSrcFilter] = useState('all')
  const [stFilter,  setStFilter]  = useState('all')
  const [atFilter,  setAtFilter]  = useState('all')
  const [refreshInterval, setRefreshInterval] = useState(10000) // 10s default
  const [limit, setLimit] = useState(50)
  const [selectedIds, setSelectedIds] = useState(new Set())

  const getAttackClass = (type) => {
    if (!type) return ''
    const t = type.toLowerCase()
    if (t.includes('scan')) return 'scan'
    if (t.includes('access')) return 'access'
    if (t.includes('ids') || t.includes('snort')) return 'ids'
    if (t.includes('endpoint') || t.includes('wazuh')) return 'endpoint'
    if (t.includes('phishing')) return 'phishing'
    if (t.includes('malware')) return 'access'
    return ''
  }

  const load = useCallback(async (isSilent = false) => {
    if (!isSilent && incidents.length === 0) setLoading(true)
    try {
      const params = {}
      if (srcFilter !== 'all') params.source = srcFilter
      if (stFilter  !== 'all') params.status = stFilter
      if (atFilter  !== 'all') params.attack_type = atFilter
      const data = await api.listIncidents({ ...params, limit })
      setIncidents(data)
    } finally {
      if (!isSilent) setLoading(false)
    }
  }, [srcFilter, stFilter, atFilter, limit, incidents.length])

  useEffect(() => { load() }, [load])

  // Auto-refresh incidents (Silent)
  useEffect(() => {
    if (refreshInterval === 0) return
    const t = setInterval(() => {
      load(true)
    }, refreshInterval)
    return () => clearInterval(t)
  }, [refreshInterval, load])

  // Open incident if navigated from Dashboard with state
  useEffect(() => {
    if (location.state?.openId && incidents.length > 0) {
      const inc = incidents.find(i => i.id === location.state.openId)
      if (inc) setSelected(inc)
    }
  }, [location.state, incidents])

  const openDetail = async (id) => {
    try {
      const full = await api.getIncident(id)
      setSelected(full)
    } catch {
      // fallback to list item
      setSelected(incidents.find(i => i.id === id))
    }
  }

  const handleDelete = async (e, id) => {
    e.stopPropagation() // Prevent opening detail
    if (!window.confirm("Are you sure you want to delete this incident?")) return
    try {
      await api.deleteIncident(id)
      setIncidents(prev => prev.filter(i => i.id !== id))
      if (selected?.id === id) setSelected(null)
      // Remove from selection if deleted
      setSelectedIds(prev => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    } catch (err) {
      alert("Failed to delete incident: " + err.message)
    }
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === incidents.length && incidents.length > 0) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(incidents.map(i => i.id)))
    }
  }

  const toggleSelectOne = (e, id) => {
    e.stopPropagation()
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return
    if (!window.confirm(`Are you sure you want to delete ${selectedIds.size} incidents?`)) return
    
    try {
      await api.deleteIncidentsBulk(Array.from(selectedIds))
      setIncidents(prev => prev.filter(i => !selectedIds.has(i.id)))
      if (selected && selectedIds.has(selected.id)) setSelected(null)
      setSelectedIds(new Set())
    } catch (err) {
      alert("Failed to delete incidents: " + err.message)
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Incidents</div>
          <div className="topbar-sub">{incidents.length} record{incidents.length !== 1 ? 's' : ''} · click any row for full analysis</div>
        </div>
        <div className="topbar-actions">
          {/* Source filter */}
          <select
            className="form-select"
            style={{ width: 140 }}
            value={srcFilter}
            onChange={e => setSrcFilter(e.target.value)}
          >
            {SOURCES.map(s => <option key={s} value={s}>{s === 'all' ? 'All Source' : s}</option>)}
          </select>
          {/* Status filter */}
          <select
            className="form-select"
            style={{ width: 140 }}
            value={stFilter}
            onChange={e => setStFilter(e.target.value)}
          >
            {STATUSES.map(s => <option key={s} value={s}>{s === 'all' ? 'All Status' : s}</option>)}
          </select>
          {/* Attack Type filter */}
          <select
            className="form-select"
            style={{ width: 160 }}
            value={atFilter}
            onChange={e => setAtFilter(e.target.value)}
          >
            {ATTACK_TYPES.map(a => <option key={a} value={a}>{a === 'all' ? 'All Attack Types' : a}</option>)}
          </select>
          {/* Refresh interval */}
          <select
            className="form-select"
            style={{ width: 140 }}
            value={refreshInterval}
            onChange={e => setRefreshInterval(Number(e.target.value))}
          >
            <option value={10000}>Refresh: 10s</option>
            <option value={30000}>Refresh: 30s</option>
            <option value={60000}>Refresh: 1m</option>
            <option value={0}>Refresh: Never</option>
          </select>
          {/* Limit selector */}
          <select
            className="form-select"
            style={{ width: 110 }}
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
          >
            <option value={20}>20 rows</option>
            <option value={50}>50 rows</option>
            <option value={200}>200 rows</option>
            <option value={1000}>All (1000)</option>
          </select>
          <button className="btn btn-secondary" onClick={load} disabled={loading}>
            <RefreshCw size={14} />
            Refresh
          </button>
          {selectedIds.size > 0 && (
            <button className="btn btn-danger" onClick={handleBulkDelete}>
              <Trash2 size={14} />
              Delete ({selectedIds.size})
            </button>
          )}
        </div>
      </div>

      <div className="page">
        <div className="table-container">
          {loading ? (
            <div className="flex-center" style={{ padding: 60 }}>
              <div className="spinner" />
            </div>
          ) : incidents.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🔍</div>
              <div className="empty-state-title">No incidents found</div>
              <div className="empty-state-sub">Try adjusting the filters or submit a new incident.</div>
            </div>
          ) : (
            <table className="incident-table">
              <thead>
                <tr>
                  <th style={{ width: 40 }}>
                    <input 
                      type="checkbox" 
                      onChange={toggleSelectAll} 
                      checked={incidents.length > 0 && selectedIds.size === incidents.length}
                    />
                  </th>
                  <th>Status</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Attack Type</th>
                  <th>Log Preview</th>
                  <th>Created</th>
                  <th>Updated</th>
                  <th style={{ width: 50 }}></th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc, idx) => (
                  <tr key={inc.id} onClick={() => openDetail(inc.id)} className={selectedIds.has(inc.id) ? 'row-selected' : ''}>
                    <td>
                      <input 
                        type="checkbox" 
                        checked={selectedIds.has(inc.id)} 
                        onChange={(e) => toggleSelectOne(e, inc.id)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </td>
                    <td><span className={`badge badge-${inc.status}`}>{inc.status}</span></td>
                    <td><span className="badge badge-unknown">{inc.source}</span></td>
                    <td><span className={`sev-${inc.severity ?? 'unknown'}`}>{(inc.severity ?? 'unknown').toUpperCase()}</span></td>
                    <td><span className={`badge badge-attack ${getAttackClass(inc.attack_type)}`}>{inc.attack_type || 'General'}</span></td>
                    <td className="mono text-xs text-muted">
                      <span className="truncate text-sm text-muted" style={{ display: 'block', maxWidth: 340 }}>
                        {inc.raw_text?.slice(0, 100)}
                      </span>
                    </td>
                    <td className="text-xs text-muted mono">{new Date(inc.created_at).toLocaleString()}</td>
                    <td className="text-xs text-muted mono">{new Date(inc.updated_at).toLocaleString()}</td>
                    <td>
                      <button 
                        className="btn btn-ghost text-danger" 
                        style={{ padding: '4px' }}
                        onClick={(e) => handleDelete(e, inc.id)}
                        title="Delete incident"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selected && (
        <IncidentPanel
          incident={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </>
  )
}
