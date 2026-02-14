package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OrgHandler struct {
	DB *pgxpool.Pool
}

func NewOrgHandler(db *pgxpool.Pool) *OrgHandler {
	return &OrgHandler{DB: db}
}

type CreateOrgRequest struct {
	Name string `json:"name"`
}

type OrgResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *OrgHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	org := OrgResponse{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Plan:      "free",
		CreatedAt: time.Now(),
	}

	if h.DB != nil {
		err := h.DB.QueryRow(r.Context(),
			`INSERT INTO organizations (id, name) VALUES ($1, $2) RETURNING created_at`,
			org.ID, org.Name,
		).Scan(&org.CreatedAt)
		if err != nil {
			http.Error(w, `{"error":"failed to create organization"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(org)
}

func (h *OrgHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]OrgResponse{})
		return
	}

	rows, err := h.DB.Query(r.Context(),
		`SELECT id, name, plan, created_at FROM organizations ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, `{"error":"failed to list organizations"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	orgs := []OrgResponse{}
	for rows.Next() {
		var org OrgResponse
		if err := rows.Scan(&org.ID, &org.Name, &org.Plan, &org.CreatedAt); err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs)
}
