import api from './client'
import type { Agent, Alert, SecurityEvent, ThreatScore, MetricPoint, Organization } from '../types'

export const organizationsApi = {
  list: () => api.get<Organization[]>('/organizations').then(r => r.data),
  create: (data: Partial<Organization>) => api.post<Organization>('/organizations', data).then(r => r.data),
}

export const agentsApi = {
  list: () => api.get<Agent[]>('/agents').then(r => r.data),
  get: (id: string) => api.get<Agent>(`/agents/${id}`).then(r => r.data),
  create: (data: Partial<Agent>) => api.post<Agent>('/agents', data).then(r => r.data),
  updateConfig: (id: string, config: Record<string, unknown>) =>
    api.put(`/agents/${id}/config`, config).then(r => r.data),
}

export const alertsApi = {
  list: (params?: { severity?: string; status?: string }) =>
    api.get<Alert[]>('/alerts', { params }).then(r => r.data),
  get: (id: string) => api.get<Alert>(`/alerts/${id}`).then(r => r.data),
  updateStatus: (id: string, status: string) =>
    api.patch(`/alerts/${id}`, { status }).then(r => r.data),
  escalate: (id: string) => api.post(`/alerts/${id}/escalate`).then(r => r.data),
}

export const eventsApi = {
  list: (params?: { source?: string; category?: string; severity?: string }) =>
    api.get<SecurityEvent[]>('/events', { params }).then(r => r.data),
}

export const metricsApi = {
  getThreatScore: (orgId: string) =>
    api.get<ThreatScore>('/threats/score', { params: { org_id: orgId } }).then(r => r.data),
  queryMetrics: (name: string, range?: string) =>
    api.get<MetricPoint[]>('/metrics', { params: { name, range } }).then(r => r.data),
  ingestEvents: (events: Partial<SecurityEvent>[]) =>
    api.post('/events/ingest', events).then(r => r.data),
}
