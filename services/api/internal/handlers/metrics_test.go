package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/handlers"
)

func TestGetThreatScoreReturns200(t *testing.T) {
	h := handlers.NewMetricsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/threat-score", nil)
	w := httptest.NewRecorder()

	h.GetThreatScore(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["score"] == nil {
		t.Error("expected score field in response")
	}
}

func TestIngestEventsReturns201(t *testing.T) {
	h := handlers.NewMetricsHandler(nil)
	body := `[{"source":"syslog","category":"auth","severity":"medium","summary":"Failed SSH login","payload":{}}]`
	req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.IngestEvents(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["ingested"] != float64(1) {
		t.Errorf("expected ingested 1, got %v", resp["ingested"])
	}
}

func TestIngestEventsRejectsEmptyBatch(t *testing.T) {
	h := handlers.NewMetricsHandler(nil)
	body := `[]`
	req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.IngestEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestListEventsReturnsEmptyArray(t *testing.T) {
	h := handlers.NewMetricsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	w := httptest.NewRecorder()

	h.ListEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp []interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty array, got %d items", len(resp))
	}
}

func TestQueryMetricsReturnsEmptyArray(t *testing.T) {
	h := handlers.NewMetricsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/?name=cpu&range=24h", nil)
	w := httptest.NewRecorder()

	h.QueryMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp []interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty array, got %d items", len(resp))
	}
}
