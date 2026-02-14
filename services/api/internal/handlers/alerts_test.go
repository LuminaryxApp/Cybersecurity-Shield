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

func TestListAlertsReturnsEmptyArray(t *testing.T) {
	h := handlers.NewAlertHandler(nil)
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

func TestUpdateAlertStatusReturns200(t *testing.T) {
	h := handlers.NewAlertHandler(nil)

	r := chi.NewRouter()
	r.Patch("/{id}", h.Update)

	body := `{"status":"acknowledged"}`
	req := httptest.NewRequest(http.MethodPatch, "/test-alert-id", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "acknowledged" {
		t.Errorf("expected status 'acknowledged', got %v", resp["status"])
	}
}

func TestUpdateAlertRejectsInvalidStatus(t *testing.T) {
	h := handlers.NewAlertHandler(nil)

	r := chi.NewRouter()
	r.Patch("/{id}", h.Update)

	body := `{"status":"invalid_status"}`
	req := httptest.NewRequest(http.MethodPatch, "/test-alert-id", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestEscalateAlertReturns200(t *testing.T) {
	h := handlers.NewAlertHandler(nil)

	r := chi.NewRouter()
	r.Post("/{id}/escalate", h.Escalate)

	req := httptest.NewRequest(http.MethodPost, "/test-alert-id/escalate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["severity"] != "critical" {
		t.Errorf("expected severity 'critical', got %v", resp["severity"])
	}
}
