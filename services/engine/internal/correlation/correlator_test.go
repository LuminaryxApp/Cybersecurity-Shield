package correlation_test

import (
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/correlation"
)

func TestCorrelatorDefaultRules(t *testing.T) {
	c := correlation.New(1000)
	if c.RuleCount() < 3 {
		t.Errorf("expected at least 3 default rules, got %d", c.RuleCount())
	}
}

func TestCorrelatorBruteForceDetection(t *testing.T) {
	c := correlation.New(1000)

	now := time.Now()
	for i := 0; i < 6; i++ {
		c.Process(core.Event{
			Time:     now.Add(time.Duration(i) * time.Second),
			OrgID:    "org-1",
			Source:   "auth",
			Category: "auth_failure",
			Severity: "medium",
			Summary:  "Failed password",
		})
	}

	results := c.GetResults()
	found := false
	for _, r := range results {
		if r.Rule == "brute_force_attack" {
			found = true
			if r.Severity != "high" {
				t.Errorf("expected severity 'high', got %s", r.Severity)
			}
		}
	}
	if !found {
		t.Error("expected brute_force_attack correlation")
	}
}

func TestCorrelatorPortScanWithExploit(t *testing.T) {
	c := correlation.New(1000)

	now := time.Now()
	c.Process(core.Event{
		Time:     now,
		OrgID:    "org-1",
		Source:   "network",
		Category: "port_scan",
		Severity: "high",
	})
	c.Process(core.Event{
		Time:     now.Add(time.Second),
		OrgID:    "org-1",
		Source:   "network",
		Category: "suspicious_port",
		Severity: "high",
	})

	results := c.GetResults()
	found := false
	for _, r := range results {
		if r.Rule == "port_scan_with_exploit" {
			found = true
			if r.Severity != "critical" {
				t.Errorf("expected severity 'critical', got %s", r.Severity)
			}
		}
	}
	if !found {
		t.Error("expected port_scan_with_exploit correlation")
	}
}

func TestCorrelatorLateralMovement(t *testing.T) {
	c := correlation.New(1000)

	now := time.Now()
	c.Process(core.Event{
		Time:     now,
		OrgID:    "org-1",
		Source:   "auth",
		Category: "auth_failure",
		Severity: "medium",
	})
	c.Process(core.Event{
		Time:     now.Add(time.Minute),
		OrgID:    "org-1",
		Source:   "auth",
		Category: "auth_success",
		Severity: "info",
	})

	results := c.GetResults()
	found := false
	for _, r := range results {
		if r.Rule == "lateral_movement" {
			found = true
		}
	}
	if !found {
		t.Error("expected lateral_movement correlation")
	}
}

func TestCorrelatorNoFalsePositives(t *testing.T) {
	c := correlation.New(1000)

	now := time.Now()
	c.Process(core.Event{
		Time:     now,
		OrgID:    "org-1",
		Source:   "syslog",
		Category: "system",
		Severity: "info",
		Summary:  "Normal log entry",
	})

	results := c.GetResults()
	if len(results) > 0 {
		t.Errorf("expected no correlations for normal events, got %d", len(results))
	}
}

func TestCorrelatorClearResults(t *testing.T) {
	c := correlation.New(1000)

	now := time.Now()
	for i := 0; i < 6; i++ {
		c.Process(core.Event{
			Time:     now.Add(time.Duration(i) * time.Second),
			OrgID:    "org-1",
			Category: "auth_failure",
		})
	}

	if len(c.GetResults()) == 0 {
		t.Error("expected results before clear")
	}

	c.ClearResults()
	if len(c.GetResults()) != 0 {
		t.Error("expected empty results after clear")
	}
}

func TestCorrelatorCustomRule(t *testing.T) {
	c := correlation.New(1000)
	c.RegisterRule(correlation.Rule{
		Name:        "test_rule",
		Description: "test",
		Window:      1 * time.Minute,
		MinEvents:   1,
		Severity:    "low",
		Category:    "test",
		Match: func(events []core.Event) bool {
			for _, e := range events {
				if e.Category == "custom_category" {
					return true
				}
			}
			return false
		},
	})

	c.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "custom_category",
	})

	results := c.GetResults()
	found := false
	for _, r := range results {
		if r.Rule == "test_rule" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom rule match")
	}
}

func TestFormatResult(t *testing.T) {
	r := correlation.CorrelationResult{
		Rule:     "test",
		Severity: "high",
		Category: "attack",
		Summary:  "Test result",
		Events:   make([]core.Event, 5),
	}
	formatted := correlation.FormatResult(r)
	if formatted == "" {
		t.Error("expected non-empty formatted string")
	}
}
