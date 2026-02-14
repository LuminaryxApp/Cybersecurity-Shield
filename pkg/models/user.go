package models

import "time"

type User struct {
	ID         string    `json:"id" db:"id"`
	KeycloakID string    `json:"keycloak_id" db:"keycloak_id"`
	OrgID      string    `json:"org_id" db:"org_id"`
	Email      string    `json:"email" db:"email"`
	Role       string    `json:"role" db:"role"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}
