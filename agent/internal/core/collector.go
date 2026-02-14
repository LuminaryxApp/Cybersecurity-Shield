package core

import (
	"context"
	"time"
)

type Event struct {
	Time      time.Time              `json:"time"`
	OrgID     string                 `json:"org_id"`
	AgentID   string                 `json:"agent_id"`
	Source    string                 `json:"source"`
	Category  string                 `json:"category"`
	Severity  string                 `json:"severity"`
	RiskScore float32                `json:"risk_score"`
	Summary   string                 `json:"summary"`
	Payload   map[string]interface{} `json:"payload"`
}

type Collector interface {
	Name() string
	Start(ctx context.Context, eventCh chan<- Event) error
	Stop() error
}
