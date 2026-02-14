package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var validStatuses = map[string]bool{
	"open":         true,
	"acknowledged": true,
	"resolved":     true,
	"escalated":    true,
}

type AlertHandler struct {
	DB *pgxpool.Pool
}

func NewAlertHandler(db *pgxpool.Pool) *AlertHandler {
	return &AlertHandler{DB: db}
}

type AlertResponse struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"org_id"`
	AgentID        *string   `json:"agent_id"`
	Severity       string    `json:"severity"`
	Title          string    `json:"title"`
	Description    *string   `json:"description"`
	LLMExplanation *string   `json:"llm_explanation"`
	LLMRemediation *string   `json:"llm_remediation"`
	Status         string    `json:"status"`
	AssigneeID     *string   `json:"assignee_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type UpdateAlertRequest struct {
	Status     string  `json:"status"`
	AssigneeID *string `json:"assignee_id"`
}

func (h *AlertHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]AlertResponse{})
		return
	}

	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")

	query := `SELECT id, org_id, agent_id, severity, title, description,
		llm_explanation, llm_remediation, status, assignee_id, created_at, updated_at
		FROM alerts WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if severity != "" {
		query += ` AND severity = $` + itoa(argIdx)
		args = append(args, severity)
		argIdx++
	}
	if status != "" {
		query += ` AND status = $` + itoa(argIdx)
		args = append(args, status)
		argIdx++
	}

	query += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, `{"error":"failed to list alerts"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	alerts := []AlertResponse{}
	for rows.Next() {
		var a AlertResponse
		if err := rows.Scan(&a.ID, &a.OrgID, &a.AgentID, &a.Severity, &a.Title,
			&a.Description, &a.LLMExplanation, &a.LLMRemediation, &a.Status,
			&a.AssigneeID, &a.CreatedAt, &a.UpdatedAt); err != nil {
			continue
		}
		alerts = append(alerts, a)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (h *AlertHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.DB == nil {
		http.Error(w, `{"error":"alert not found"}`, http.StatusNotFound)
		return
	}

	var a AlertResponse
	err := h.DB.QueryRow(r.Context(),
		`SELECT id, org_id, agent_id, severity, title, description,
			llm_explanation, llm_remediation, status, assignee_id, created_at, updated_at
		 FROM alerts WHERE id = $1`, id,
	).Scan(&a.ID, &a.OrgID, &a.AgentID, &a.Severity, &a.Title,
		&a.Description, &a.LLMExplanation, &a.LLMRemediation, &a.Status,
		&a.AssigneeID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		http.Error(w, `{"error":"alert not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a)
}

func (h *AlertHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req UpdateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if req.Status != "" && !validStatuses[req.Status] {
		http.Error(w, `{"error":"invalid status, must be one of: open, acknowledged, resolved, escalated"}`, http.StatusBadRequest)
		return
	}

	if h.DB != nil {
		_, err := h.DB.Exec(r.Context(),
			`UPDATE alerts SET status = $1, assignee_id = COALESCE($2, assignee_id), updated_at = NOW() WHERE id = $3`,
			req.Status, req.AssigneeID, id,
		)
		if err != nil {
			http.Error(w, `{"error":"failed to update alert"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"status": req.Status,
	})
}

func (h *AlertHandler) Escalate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.DB != nil {
		_, err := h.DB.Exec(r.Context(),
			`UPDATE alerts SET severity = 'critical', status = 'escalated', updated_at = NOW() WHERE id = $1`,
			id,
		)
		if err != nil {
			http.Error(w, `{"error":"failed to escalate alert"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       id,
		"severity": "critical",
		"status":   "escalated",
	})
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
