// src/api.js – centralized API client pointing at FastAPI backend

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body?.detail?.message || body?.detail || `HTTP ${res.status}`)
  }
  if (res.status === 204) {
    return null
  }
  return res.json()
}

export const api = {
  health:       ()              => request('/api/health'),
  getStats:     ()              => request('/api/v1/stats'),
  listIncidents:(params = {})   => {
    const q = new URLSearchParams()
    if (params.status)  q.set('status',  params.status)
    if (params.source)  q.set('source',  params.source)
    if (params.limit)   q.set('limit',   params.limit)
    return request(`/api/v1/incidents?${q}`)
  },
  getIncident:  (id)            => request(`/api/v1/incidents/${id}`),
  deleteIncident: (id)          => request(`/api/v1/incidents/${id}`, { method: 'DELETE' }),
  deleteIncidentsBulk: (ids)    => request('/api/v1/incidents/bulk-delete', { method: 'POST', body: JSON.stringify({ ids }) }),
  analyzeManual:(body)          => request('/api/v1/analyze', { method: 'POST', body: JSON.stringify(body) }),
  getKeys:      ()              => request('/api/v1/settings/keys'),
  updateKeys:   (body)          => request('/api/v1/settings/keys', { method: 'POST', body: JSON.stringify(body) }),
}
