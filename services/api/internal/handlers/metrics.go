package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type MetricsHandler struct {
	DB *pgxpool.Pool
}

func NewMetricsHandler(db *pgxpool.Pool) *MetricsHandler {
	return &MetricsHandler{DB: db}
}

type EventIngest struct {
	Source   string                 `json:"source"`
	Category string                `json:"category"`
	Severity string                `json:"severity"`
	Summary  string                `json:"summary"`
	Payload  map[string]interface{} `json:"payload"`
}

type MetricPoint struct {
	Time        time.Time `json:"time"`
	MetricName  string    `json:"metric_name"`
	MetricValue float64   `json:"metric_value"`
}

type EventResponse struct {
	Time      time.Time              `json:"time"`
	OrgID     string                 `json:"org_id"`
	AgentID   string                 `json:"agent_id"`
	Source    string                 `json:"source"`
	Category  string                 `json:"category"`
	Severity  string                 `json:"severity"`
	RiskScore float32                `json:"risk_score"`
	Summary   *string                `json:"summary"`
	Payload   map[string]interface{} `json:"payload"`
}

func (h *MetricsHandler) GetThreatScore(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"score":   100.0,
			"trend":   0.0,
			"factors": map[string]interface{}{},
		})
		return
	}

	var score float32
	var factors []byte
	err := h.DB.QueryRow(r.Context(),
		`SELECT score, factors FROM threat_scores
		 WHERE org_id = $1 ORDER BY time DESC LIMIT 1`,
		r.URL.Query().Get("org_id"),
	).Scan(&score, &factors)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"score":   100.0,
			"trend":   0.0,
			"factors": map[string]interface{}{},
		})
		return
	}

	var factorsMap map[string]interface{}
	json.Unmarshal(factors, &factorsMap)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"score":   score,
		"trend":   0.0,
		"factors": factorsMap,
	})
}

func (h *MetricsHandler) IngestEvents(w http.ResponseWriter, r *http.Request) {
	var events []EventIngest
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if len(events) == 0 {
		http.Error(w, `{"error":"empty event batch"}`, http.StatusBadRequest)
		return
	}

	if h.DB != nil {
		for _, e := range events {
			payloadJSON, _ := json.Marshal(e.Payload)
			_, err := h.DB.Exec(r.Context(),
				`INSERT INTO events (time, org_id, agent_id, source, category, severity, summary, payload)
				 VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7)`,
				r.URL.Query().Get("org_id"),
				r.URL.Query().Get("agent_id"),
				e.Source, e.Category, e.Severity, e.Summary, payloadJSON,
			)
			if err != nil {
				http.Error(w, `{"error":"failed to ingest events"}`, http.StatusInternalServerError)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ingested": len(events),
	})
}

func (h *MetricsHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]EventResponse{})
		return
	}

	source := r.URL.Query().Get("source")
	category := r.URL.Query().Get("category")
	severity := r.URL.Query().Get("severity")

	query := `SELECT time, org_id, agent_id, source, category, severity, risk_score, summary, payload
		FROM events WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if source != "" {
		query += ` AND source = $` + fmt.Sprintf("%d", argIdx)
		args = append(args, source)
		argIdx++
	}
	if category != "" {
		query += ` AND category = $` + fmt.Sprintf("%d", argIdx)
		args = append(args, category)
		argIdx++
	}
	if severity != "" {
		query += ` AND severity = $` + fmt.Sprintf("%d", argIdx)
		args = append(args, severity)
		argIdx++
	}

	query += ` ORDER BY time DESC LIMIT 500`

	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, `{"error":"failed to list events"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := []EventResponse{}
	for rows.Next() {
		var e EventResponse
		var payloadJSON []byte
		if err := rows.Scan(&e.Time, &e.OrgID, &e.AgentID, &e.Source, &e.Category,
			&e.Severity, &e.RiskScore, &e.Summary, &payloadJSON); err != nil {
			continue
		}
		json.Unmarshal(payloadJSON, &e.Payload)
		events = append(events, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (h *MetricsHandler) QueryMetrics(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]MetricPoint{})
		return
	}

	name := r.URL.Query().Get("name")
	rangeStr := r.URL.Query().Get("range")

	interval := "24h"
	if rangeStr != "" {
		interval = rangeStr
	}

	var duration string
	switch interval {
	case "1h":
		duration = "1 hour"
	case "6h":
		duration = "6 hours"
	case "24h":
		duration = "24 hours"
	case "7d":
		duration = "7 days"
	case "30d":
		duration = "30 days"
	default:
		duration = "24 hours"
	}

	rows, err := h.DB.Query(r.Context(),
		`SELECT time, metric_name, metric_value FROM metrics
		 WHERE metric_name = $1 AND time > NOW() - $2::interval
		 ORDER BY time ASC`,
		name, duration,
	)
	if err != nil {
		http.Error(w, `{"error":"failed to query metrics"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	metrics := []MetricPoint{}
	for rows.Next() {
		var m MetricPoint
		if err := rows.Scan(&m.Time, &m.MetricName, &m.MetricValue); err != nil {
			continue
		}
		metrics = append(metrics, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}
