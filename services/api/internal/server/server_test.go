package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/server"
)

func TestHealthEndpoint(t *testing.T) {
	srv := server.New(nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
