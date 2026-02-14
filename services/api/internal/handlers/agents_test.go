package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/handlers"
	"github.com/go-chi/chi/v5"
)

func TestCreateAgentReturns201(t *testing.T) {
	h := handlers.NewAgentHandler(nil)
	body := `{"name":"Office Network Agent","org_id":"test-org-123"}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["name"] != "Office Network Agent" {
		t.Errorf("expected name 'Office Network Agent', got %v", resp["name"])
	}
	if resp["status"] != "pending" {
		t.Errorf("expected status 'pending', got %v", resp["status"])
	}
}

func TestCreateAgentRejectsMissingName(t *testing.T) {
	h := handlers.NewAgentHandler(nil)
	body := `{"org_id":"test-org-123"}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestListAgentsReturnsEmptyArray(t *testing.T) {
	h := handlers.NewAgentHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp []interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty array, got %d items", len(resp))
	}
}

func TestHeartbeatReturns200(t *testing.T) {
	h := handlers.NewAgentHandler(nil)

	r := chi.NewRouter()
	r.Patch("/{id}/heartbeat", h.Heartbeat)

	req := httptest.NewRequest(http.MethodPatch, "/test-agent-id/heartbeat", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
