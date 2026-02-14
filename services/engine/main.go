package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/alerts"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/config"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/correlation"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/scoring"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func main() {
	cfg := config.Load()

	opts := []nats.Option{}
	if cfg.NATSToken != "" {
		opts = append(opts, nats.Token(cfg.NATSToken))
	}

	nc, err := nats.Connect(cfg.NATSUrl, opts...)
	if err != nil {
		log.Fatalf("failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	var db *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		var dbErr error
		db, dbErr = pgxpool.New(context.Background(), cfg.DatabaseURL)
		if dbErr != nil {
			log.Printf("warning: failed to connect to database: %v", dbErr)
		} else {
			defer db.Close()
		}
	}

	engine := core.New(nc, db)

	correlator := correlation.New(10000)
	scorer := scoring.New(parseDuration(cfg.ScoringWindow))
	alertGen := alerts.NewAlertGenerator(cfg.APIURL, cfg.AlertWebhook, 5.0)

	engine.RegisterPipeline("correlation", func(event core.Event) error {
		return correlator.Process(event)
	})

	engine.RegisterPipeline("scoring", func(event core.Event) error {
		return scorer.Process(event)
	})

	engine.RegisterPipeline("alerting", func(event core.Event) error {
		return alertGen.ProcessEvent(event)
	})

	go func() {
		for result := range correlator.Results() {
			alertGen.ProcessCorrelation(result)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := engine.Start(ctx); err != nil {
		log.Fatalf("failed to start engine: %v", err)
	}

	log.Println("Analysis Engine started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down engine...")
	engine.Stop()
}

func parseDuration(s string) time.Duration {
	switch s {
	case "1h":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
