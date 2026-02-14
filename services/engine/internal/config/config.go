package config

import "os"

type Config struct {
	NATSUrl        string
	NATSToken      string
	DatabaseURL    string
	APIURL         string
	LLMProvider    string
	LLMAPIKey      string
	LLMModel       string
	AlertWebhook   string
	ScoringWindow  string
}

func Load() *Config {
	return &Config{
		NATSUrl:       getEnv("NATS_URL", "nats://localhost:4222"),
		NATSToken:     getEnv("NATS_TOKEN", ""),
		DatabaseURL:   getEnv("DATABASE_URL", "postgres://shield:shield@localhost:5432/cybershield?sslmode=disable"),
		APIURL:        getEnv("API_URL", "http://localhost:8080"),
		LLMProvider:   getEnv("LLM_PROVIDER", "anthropic"),
		LLMAPIKey:     getEnv("LLM_API_KEY", ""),
		LLMModel:      getEnv("LLM_MODEL", "claude-sonnet-4-20250514"),
		AlertWebhook:  getEnv("ALERT_WEBHOOK", ""),
		ScoringWindow: getEnv("SCORING_WINDOW", "24h"),
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
