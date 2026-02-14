package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AgentHandler struct {
	DB *pgxpool.Pool
}

func NewAgentHandler(db *pgxpool.Pool) *AgentHandler {
	return &AgentHandler{DB: db}
}

type CreateAgentRequest struct {
	Name  string                 `json:"name"`
	OrgID string                 `json:"org_id"`
	Config map[string]interface{} `json:"config"`
}

type AgentResponse struct {
	ID            string                 `json:"id"`
	OrgID         string                 `json:"org_id"`
	Name          string                 `json:"name"`
	Status        string                 `json:"status"`
	LastHeartbeat *time.Time             `json:"last_heartbeat"`
	Config        map[string]interface{} `json:"config"`
	CreatedAt     time.Time              `json:"created_at"`
}

func (h *AgentHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	if req.Config == nil {
		req.Config = map[string]interface{}{}
	}

	agent := AgentResponse{
		ID:        uuid.New().String(),
		OrgID:     req.OrgID,
		Name:      req.Name,
		Status:    "pending",
		Config:    req.Config,
		CreatedAt: time.Now(),
	}

	if h.DB != nil {
		configJSON, _ := json.Marshal(req.Config)
		err := h.DB.QueryRow(r.Context(),
			`INSERT INTO agents (id, org_id, name, config) VALUES ($1, $2, $3, $4) RETURNING created_at`,
			agent.ID, agent.OrgID, agent.Name, configJSON,
		).Scan(&agent.CreatedAt)
		if err != nil {
			http.Error(w, `{"error":"failed to create agent"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(agent)
}

func (h *AgentHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]AgentResponse{})
		return
	}

	rows, err := h.DB.Query(r.Context(),
		`SELECT id, org_id, name, status, last_heartbeat, config, created_at
		 FROM agents ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, `{"error":"failed to list agents"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	agents := []AgentResponse{}
	for rows.Next() {
		var a AgentResponse
		var configJSON []byte
		if err := rows.Scan(&a.ID, &a.OrgID, &a.Name, &a.Status, &a.LastHeartbeat, &configJSON, &a.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(configJSON, &a.Config)
		agents = append(agents, a)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func (h *AgentHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.DB == nil {
		http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
		return
	}

	var a AgentResponse
	var configJSON []byte
	err := h.DB.QueryRow(r.Context(),
		`SELECT id, org_id, name, status, last_heartbeat, config, created_at
		 FROM agents WHERE id = $1`, id,
	).Scan(&a.ID, &a.OrgID, &a.Name, &a.Status, &a.LastHeartbeat, &configJSON, &a.CreatedAt)
	if err != nil {
		http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
		return
	}
	json.Unmarshal(configJSON, &a.Config)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a)
}

func (h *AgentHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := time.Now()

	if h.DB != nil {
		_, err := h.DB.Exec(r.Context(),
			`UPDATE agents SET last_heartbeat = $1, status = 'online', updated_at = $1 WHERE id = $2`,
			now, id,
		)
		if err != nil {
			http.Error(w, `{"error":"failed to update heartbeat"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":             id,
		"last_heartbeat": now,
		"status":         "online",
	})
}

func (h *AgentHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if h.DB != nil {
		configJSON, _ := json.Marshal(config)
		_, err := h.DB.Exec(r.Context(),
			`UPDATE agents SET config = $1, updated_at = NOW() WHERE id = $2`,
			configJSON, id,
		)
		if err != nil {
			http.Error(w, `{"error":"failed to update config"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"config": config,
	})
}
