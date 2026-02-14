package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/handlers"
)

type Server struct {
	Router *chi.Mux
	DB     *pgxpool.Pool
	WSHub  *handlers.WSHub
}

func New(db *pgxpool.Pool) *Server {
	s := &Server{
		Router: chi.NewRouter(),
		DB:     db,
		WSHub:  handlers.NewWSHub(),
	}

	s.Router.Use(middleware.Logger)
	s.Router.Use(middleware.Recoverer)
	s.Router.Use(middleware.RequestID)

	s.Router.Get("/health", s.handleHealth)

	s.mountRoutes()

	return s
}

func (s *Server) mountRoutes() {
	orgHandler := handlers.NewOrgHandler(s.DB)
	agentHandler := handlers.NewAgentHandler(s.DB)
	alertHandler := handlers.NewAlertHandler(s.DB)
	metricsHandler := handlers.NewMetricsHandler(s.DB)

	s.Router.Route("/api/v1", func(r chi.Router) {
		r.Route("/organizations", func(r chi.Router) {
			r.Post("/", orgHandler.Create)
			r.Get("/", orgHandler.List)
		})
		r.Route("/agents", func(r chi.Router) {
			r.Post("/", agentHandler.Create)
			r.Get("/", agentHandler.List)
			r.Get("/{id}", agentHandler.Get)
			r.Patch("/{id}/heartbeat", agentHandler.Heartbeat)
			r.Put("/{id}/config", agentHandler.UpdateConfig)
		})
		r.Route("/alerts", func(r chi.Router) {
			r.Get("/", alertHandler.List)
			r.Get("/{id}", alertHandler.Get)
			r.Patch("/{id}", alertHandler.Update)
			r.Post("/{id}/escalate", alertHandler.Escalate)
		})
		r.Route("/metrics", func(r chi.Router) {
			r.Get("/", metricsHandler.QueryMetrics)
			r.Get("/threat-score", metricsHandler.GetThreatScore)
		})
		r.Route("/events", func(r chi.Router) {
			r.Post("/", metricsHandler.IngestEvents)
			r.Get("/", metricsHandler.ListEvents)
		})
		r.Route("/threats", func(r chi.Router) {})
		r.Route("/settings", func(r chi.Router) {})
	})

	s.Router.Get("/ws", s.WSHub.HandleWS)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
