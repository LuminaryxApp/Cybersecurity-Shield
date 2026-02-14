package alerts_test

import (
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/alerts"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/correlation"
)

func TestAlertGeneratorCreation(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)
	if g == nil {
		t.Fatal("expected non-nil generator")
	}
	if g.AlertCount() != 0 {
		t.Errorf("expected 0 alerts, got %d", g.AlertCount())
	}
}

func TestAlertGeneratorHighSeverity(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)

	err := g.ProcessEvent(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		AgentID:  "agent-1",
		Source:   "auth",
		Category: "auth_brute_force",
		Severity: "high",
		Summary:  "Brute force detected",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.AlertCount() != 1 {
		t.Errorf("expected 1 alert, got %d", g.AlertCount())
	}

	alertList := g.GetAlerts()
	if len(alertList) != 1 {
		t.Fatalf("expected 1 alert in list, got %d", len(alertList))
	}

	alert := alertList[0]
	if alert.Severity != "high" {
		t.Errorf("expected severity 'high', got %s", alert.Severity)
	}
	if alert.Status != "open" {
		t.Errorf("expected status 'open', got %s", alert.Status)
	}
}

func TestAlertGeneratorLowSeverityFiltered(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)

	g.ProcessEvent(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Source:   "syslog",
		Category: "system",
		Severity: "info",
		Summary:  "Normal log entry",
	})

	if g.AlertCount() != 0 {
		t.Errorf("expected 0 alerts for low-risk event, got %d", g.AlertCount())
	}
}

func TestAlertGeneratorDeduplication(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)

	for i := 0; i < 5; i++ {
		g.ProcessEvent(core.Event{
			Time:     time.Now(),
			OrgID:    "org-1",
			Source:   "auth",
			Category: "auth_brute_force",
			Severity: "high",
			Summary:  "Brute force detected",
		})
	}

	if g.AlertCount() != 1 {
		t.Errorf("expected 1 alert (deduped), got %d", g.AlertCount())
	}
}

func TestAlertGeneratorCorrelation(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)

	result := correlation.CorrelationResult{
		Rule:     "brute_force_attack",
		Severity: "critical",
		Category: "attack",
		Summary:  "Correlated brute force",
		Events: []core.Event{
			{OrgID: "org-1", AgentID: "agent-1", Category: "auth_failure"},
			{OrgID: "org-1", AgentID: "agent-1", Category: "auth_failure"},
		},
	}

	err := g.ProcessCorrelation(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.AlertCount() != 1 {
		t.Errorf("expected 1 alert, got %d", g.AlertCount())
	}

	alertList := g.GetAlerts()
	alert := alertList[0]
	if alert.Source != "correlation" {
		t.Errorf("expected source 'correlation', got %s", alert.Source)
	}
	if alert.EventCount != 2 {
		t.Errorf("expected event count 2, got %d", alert.EventCount)
	}
}

func TestAlertChannel(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)

	g.ProcessEvent(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Source:   "network",
		Category: "port_scan",
		Severity: "high",
	})

	select {
	case alert := <-g.Alerts():
		if alert.Category != "port_scan" {
			t.Errorf("expected category 'port_scan', got %s", alert.Category)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for alert on channel")
	}
}

func TestAlertGeneratorCriticalEvent(t *testing.T) {
	g := alerts.NewAlertGenerator("", "", 5.0)

	g.ProcessEvent(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Source:   "cloud",
		Category: "misconfiguration",
		Severity: "critical",
	})

	if g.AlertCount() != 1 {
		t.Errorf("expected 1 alert for critical event, got %d", g.AlertCount())
	}
}
