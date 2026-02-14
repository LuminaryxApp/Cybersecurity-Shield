package models

import "time"

type Agent struct {
	ID            string                 `json:"id" db:"id"`
	OrgID         string                 `json:"org_id" db:"org_id"`
	Name          string                 `json:"name" db:"name"`
	Status        string                 `json:"status" db:"status"`
	LastHeartbeat *time.Time             `json:"last_heartbeat" db:"last_heartbeat"`
	Config        map[string]interface{} `json:"config" db:"config"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}
