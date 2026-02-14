package models

import "time"

type Event struct {
	Time      time.Time              `json:"time" db:"time"`
	OrgID     string                 `json:"org_id" db:"org_id"`
	AgentID   string                 `json:"agent_id" db:"agent_id"`
	Source    string                 `json:"source" db:"source"`
	Category  string                 `json:"category" db:"category"`
	Severity  string                 `json:"severity" db:"severity"`
	RiskScore float32                `json:"risk_score" db:"risk_score"`
	Summary   *string                `json:"summary" db:"summary"`
	Payload   map[string]interface{} `json:"payload" db:"payload"`
}

type Metric struct {
	Time        time.Time              `json:"time" db:"time"`
	OrgID       string                 `json:"org_id" db:"org_id"`
	AgentID     string                 `json:"agent_id" db:"agent_id"`
	MetricName  string                 `json:"metric_name" db:"metric_name"`
	MetricValue float64                `json:"metric_value" db:"metric_value"`
	Tags        map[string]interface{} `json:"tags" db:"tags"`
}

type ThreatScore struct {
	Time    time.Time              `json:"time" db:"time"`
	OrgID   string                 `json:"org_id" db:"org_id"`
	Score   float32                `json:"score" db:"score"`
	Factors map[string]interface{} `json:"factors" db:"factors"`
}
