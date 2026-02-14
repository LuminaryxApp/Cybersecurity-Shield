export interface Organization {
  id: string
  name: string
  plan: string
  created_at: string
}

export interface Agent {
  id: string
  org_id: string
  name: string
  hostname: string
  ip_address: string
  os: string
  status: string
  version: string
  last_heartbeat: string
  config: Record<string, unknown>
  created_at: string
}

export interface Alert {
  id: string
  org_id: string
  agent_id: string
  title: string
  description: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  category: string
  status: 'open' | 'acknowledged' | 'resolved' | 'dismissed'
  source: string
  risk_score: number
  event_count: number
  created_at: string
  updated_at: string
}

export interface SecurityEvent {
  time: string
  org_id: string
  agent_id: string
  source: string
  category: string
  severity: string
  risk_score: number
  summary: string | null
  payload: Record<string, unknown>
}

export interface ThreatScore {
  score: number
  trend: number
  factors: Record<string, number>
}

export interface MetricPoint {
  time: string
  metric_name: string
  metric_value: number
}
