package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/auth"
)

func TestRejectsMissingToken(t *testing.T) {
	handler := auth.Middleware("http://localhost:8180", "cybershield")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRejectsMalformedToken(t *testing.T) {
	handler := auth.Middleware("http://localhost:8180", "cybershield")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
