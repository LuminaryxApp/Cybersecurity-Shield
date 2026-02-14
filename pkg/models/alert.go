package models

import "time"

type Alert struct {
	ID             string    `json:"id" db:"id"`
	OrgID          string    `json:"org_id" db:"org_id"`
	AgentID        *string   `json:"agent_id" db:"agent_id"`
	Severity       string    `json:"severity" db:"severity"`
	Title          string    `json:"title" db:"title"`
	Description    *string   `json:"description" db:"description"`
	LLMExplanation *string   `json:"llm_explanation" db:"llm_explanation"`
	LLMRemediation *string   `json:"llm_remediation" db:"llm_remediation"`
	Status         string    `json:"status" db:"status"`
	AssigneeID     *string   `json:"assignee_id" db:"assignee_id"`
	SourceEvents   []string  `json:"source_events" db:"source_events"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

type AlertRule struct {
	ID                string    `json:"id" db:"id"`
	OrgID             string    `json:"org_id" db:"org_id"`
	Name              string    `json:"name" db:"name"`
	SeverityThreshold string    `json:"severity_threshold" db:"severity_threshold"`
	Channels          []string  `json:"channels" db:"channels"`
	Enabled           bool      `json:"enabled" db:"enabled"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}
