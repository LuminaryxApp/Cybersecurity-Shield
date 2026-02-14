package config

import "os"

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
		NetworkInterface:  getEnv("NETWORK_INTERFACE", ""),
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
