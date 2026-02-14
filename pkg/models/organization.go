package models

import "time"

type Organization struct {
	ID        string                 `json:"id" db:"id"`
	Name      string                 `json:"name" db:"name"`
	Plan      string                 `json:"plan" db:"plan"`
	Settings  map[string]interface{} `json:"settings" db:"settings"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}
