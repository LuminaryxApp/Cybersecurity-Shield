package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/handlers"
)

func TestCreateOrgReturns201(t *testing.T) {
	h := handlers.NewOrgHandler(nil)
	body := `{"name":"Test Corp"}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["name"] != "Test Corp" {
		t.Errorf("expected name 'Test Corp', got %v", resp["name"])
	}
}

func TestCreateOrgRejectsMissingName(t *testing.T) {
	h := handlers.NewOrgHandler(nil)
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
