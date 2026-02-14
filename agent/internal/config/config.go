package config

import (
	"os"
	"strings"
)

type Config struct {
	AgentID           string
	OrgID             string
	APIURL            string
	NATSUrl           string
	NATSToken         string
	HeartbeatInterval int
	EnableLogs        bool
	EnableNetwork     bool
	EnableCloud       bool
	CloudProvider     string
	LogSources        []string
	NetworkInterface  string
}

func Load() *Config {
	return &Config{
		AgentID:           getEnv("AGENT_ID", ""),
		OrgID:             getEnv("ORG_ID", ""),
		APIURL:            getEnv("API_URL", "http://localhost:8080"),
		NATSUrl:           getEnv("NATS_URL", "nats://localhost:4222"),
		NATSToken:         getEnv("NATS_TOKEN", ""),
		HeartbeatInterval: 30,
		EnableLogs:        getEnv("ENABLE_LOGS", "true") == "true",
		EnableNetwork:     getEnv("ENABLE_NETWORK", "true") == "true",
		EnableCloud:       getEnv("ENABLE_CLOUD", "false") == "true",
		CloudProvider:     getEnv("CLOUD_PROVIDER", ""),
		LogSources:        parseList(getEnv("LOG_SOURCES", "")),
		NetworkInterface:  getEnv("NETWORK_INTERFACE", ""),
	}
}

func parseList(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
