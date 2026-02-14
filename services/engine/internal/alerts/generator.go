package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/correlation"
)

type Alert struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"org_id"`
	AgentID     string                 `json:"agent_id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Status      string                 `json:"status"`
	Source      string                 `json:"source"`
	RiskScore   float64                `json:"risk_score"`
	EventCount  int                    `json:"event_count"`
	Payload     map[string]interface{} `json:"payload"`
	CreatedAt   time.Time              `json:"created_at"`
}

type AlertGenerator struct {
	mu          sync.RWMutex
	alerts      []Alert
	apiURL      string
	webhookURL  string
	threshold   float64
	alertCh     chan Alert
	dedup       map[string]time.Time
	dedupWindow time.Duration
}

func NewAlertGenerator(apiURL, webhookURL string, threshold float64) *AlertGenerator {
	if threshold <= 0 {
		threshold = 5.0
	}
	return &AlertGenerator{
		apiURL:      apiURL,
		webhookURL:  webhookURL,
		threshold:   threshold,
		alertCh:     make(chan Alert, 100),
		dedup:       make(map[string]time.Time),
		dedupWindow: 5 * time.Minute,
	}
}

func (g *AlertGenerator) ProcessEvent(event core.Event) error {
	riskScore := calculateEventRisk(event)

	if riskScore < g.threshold {
		return nil
	}

	alert := Alert{
		ID:          fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		OrgID:       event.OrgID,
		AgentID:     event.AgentID,
		Title:       generateTitle(event),
		Description: event.Summary,
		Severity:    event.Severity,
		Category:    event.Category,
		Status:      "open",
		Source:      event.Source,
		RiskScore:   riskScore,
		EventCount:  1,
		Payload:     event.Payload,
		CreatedAt:   time.Now(),
	}

	return g.emitAlert(alert)
}

func (g *AlertGenerator) ProcessCorrelation(result correlation.CorrelationResult) error {
	orgID := ""
	agentID := ""
	if len(result.Events) > 0 {
		orgID = result.Events[0].OrgID
		agentID = result.Events[0].AgentID
	}

	alert := Alert{
		ID:          fmt.Sprintf("cor-%d", time.Now().UnixNano()),
		OrgID:       orgID,
		AgentID:     agentID,
		Title:       "Correlated: " + result.Rule,
		Description: result.Summary,
		Severity:    result.Severity,
		Category:    result.Category,
		Status:      "open",
		Source:      "correlation",
		RiskScore:   correlationRisk(result),
		EventCount:  len(result.Events),
		CreatedAt:   time.Now(),
	}

	return g.emitAlert(alert)
}

func (g *AlertGenerator) emitAlert(alert Alert) error {
	dedupKey := fmt.Sprintf("%s-%s-%s", alert.OrgID, alert.Category, alert.Severity)

	g.mu.Lock()
	if lastTime, exists := g.dedup[dedupKey]; exists {
		if time.Since(lastTime) < g.dedupWindow {
			g.mu.Unlock()
			return nil
		}
	}
	g.dedup[dedupKey] = time.Now()
	g.alerts = append(g.alerts, alert)
	g.mu.Unlock()

	select {
	case g.alertCh <- alert:
	default:
	}

	go g.sendToAPI(alert)
	go g.sendWebhook(alert)

	return nil
}

func (g *AlertGenerator) sendToAPI(alert Alert) {
	if g.apiURL == "" {
		return
	}

	body, err := json.Marshal(alert)
	if err != nil {
		log.Printf("alert generator: failed to marshal alert: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/alerts", g.apiURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alert generator: failed to send to API: %v", err)
		return
	}
	resp.Body.Close()
}

func (g *AlertGenerator) sendWebhook(alert Alert) {
	if g.webhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("[%s] %s: %s", alert.Severity, alert.Title, alert.Description),
		"alert": alert,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	resp, err := http.Post(g.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alert generator: webhook failed: %v", err)
		return
	}
	resp.Body.Close()
}

func (g *AlertGenerator) Alerts() <-chan Alert {
	return g.alertCh
}

func (g *AlertGenerator) GetAlerts() []Alert {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]Alert, len(g.alerts))
	copy(result, g.alerts)
	return result
}

func (g *AlertGenerator) AlertCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.alerts)
}

func calculateEventRisk(event core.Event) float64 {
	base := 0.0
	switch event.Severity {
	case "info":
		base = 0.0
	case "low":
		base = 2.0
	case "medium":
		base = 5.0
	case "high":
		base = 8.0
	case "critical":
		base = 10.0
	}

	switch event.Category {
	case "attack", "auth_brute_force", "port_scan":
		base *= 1.5
	case "misconfiguration":
		base *= 1.2
	case "suspicious_port":
		base *= 1.4
	}

	return base
}

func correlationRisk(result correlation.CorrelationResult) float64 {
	base := 0.0
	switch result.Severity {
	case "medium":
		base = 6.0
	case "high":
		base = 8.0
	case "critical":
		base = 10.0
	}
	eventFactor := float64(len(result.Events)) * 0.5
	if eventFactor > 5 {
		eventFactor = 5
	}
	return base + eventFactor
}

func generateTitle(event core.Event) string {
	switch event.Category {
	case "auth_failure":
		return "Authentication Failure Detected"
	case "auth_brute_force":
		return "Brute Force Attack Detected"
	case "auth_success":
		return "Successful Authentication"
	case "port_scan":
		return "Port Scan Detected"
	case "suspicious_port":
		return "Suspicious Port Connection"
	case "misconfiguration":
		return "Cloud Misconfiguration Found"
	case "web_error":
		return "Web Service Errors"
	case "high_traffic":
		return "Abnormal Traffic Pattern"
	default:
		return "Security Event: " + event.Category
	}
}
