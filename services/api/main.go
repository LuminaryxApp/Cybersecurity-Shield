package main

import (
	"context"
	"log"
	"net/http"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/config"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/database"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/server"
)

func main() {
	cfg := config.Load()

	ctx := context.Background()
	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	srv := server.New(db)

	log.Printf("API server starting on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, srv.Router); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
