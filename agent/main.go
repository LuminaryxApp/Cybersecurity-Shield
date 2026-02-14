package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/config"
	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
	"github.com/nats-io/nats.go"
)

func main() {
	cfg := config.Load()

	var nc *nats.Conn
	var err error

	opts := []nats.Option{}
	if cfg.NATSToken != "" {
		opts = append(opts, nats.Token(cfg.NATSToken))
	}

	nc, err = nats.Connect(cfg.NATSUrl, opts...)
	if err != nil {
		log.Fatalf("failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	agent := core.New(cfg.AgentID, cfg.OrgID, cfg.APIURL, nc, cfg.HeartbeatInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		log.Fatalf("failed to start agent: %v", err)
	}

	log.Printf("Shield Agent started (id=%s, org=%s)", cfg.AgentID, cfg.OrgID)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down agent...")
	agent.Stop()
}
