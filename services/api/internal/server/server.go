package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	Router *chi.Mux
	DB     *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Server {
	s := &Server{
		Router: chi.NewRouter(),
		DB:     db,
	}

	s.Router.Use(middleware.Logger)
	s.Router.Use(middleware.Recoverer)
	s.Router.Use(middleware.RequestID)

	s.Router.Get("/health", s.handleHealth)

	s.mountRoutes()

	return s
}

func (s *Server) mountRoutes() {
	s.Router.Route("/api/v1", func(r chi.Router) {
		r.Route("/organizations", func(r chi.Router) {})
		r.Route("/agents", func(r chi.Router) {})
		r.Route("/alerts", func(r chi.Router) {})
		r.Route("/threats", func(r chi.Router) {})
		r.Route("/metrics", func(r chi.Router) {})
		r.Route("/settings", func(r chi.Router) {})
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
