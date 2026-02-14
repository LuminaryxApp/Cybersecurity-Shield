package config

import "os"

type Config struct {
	Port        string
	DatabaseURL string
	NATSUrl     string
	NATSToken   string
	KeycloakURL string
}

func Load() *Config {
	return &Config{
		Port:        getEnv("API_PORT", "8080"),
		DatabaseURL: getEnv("API_DB_URL", "postgres://shield:shield_dev_password@localhost:5432/cybershield?sslmode=disable"),
		NATSUrl:     getEnv("NATS_URL", "nats://localhost:4222"),
		NATSToken:   getEnv("NATS_TOKEN", ""),
		KeycloakURL: getEnv("KEYCLOAK_URL", "http://localhost:8180"),
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
