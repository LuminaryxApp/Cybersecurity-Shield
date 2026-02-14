package correlation

import (
	"fmt"
	"sync"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
)

type Rule struct {
	Name        string
	Description string
	Window      time.Duration
	MinEvents   int
	Match       func(events []core.Event) bool
	Severity    string
	Category    string
}

type CorrelationResult struct {
	Rule      string
	Events    []core.Event
	Severity  string
	Category  string
	Summary   string
	Timestamp time.Time
}

type Correlator struct {
	mu        sync.RWMutex
	rules     []Rule
	buffer    map[string][]core.Event
	results   []CorrelationResult
	maxBuffer int
	resultCh  chan CorrelationResult
}

func New(maxBuffer int) *Correlator {
	if maxBuffer <= 0 {
		maxBuffer = 10000
	}
	c := &Correlator{
		buffer:    make(map[string][]core.Event),
		maxBuffer: maxBuffer,
		resultCh:  make(chan CorrelationResult, 100),
	}
	c.registerDefaultRules()
	return c
}

func (c *Correlator) RegisterRule(rule Rule) {
	c.rules = append(c.rules, rule)
}

func (c *Correlator) Process(event core.Event) error {
	c.mu.Lock()
	key := event.OrgID
	c.buffer[key] = append(c.buffer[key], event)

	if len(c.buffer[key]) > c.maxBuffer {
		c.buffer[key] = c.buffer[key][len(c.buffer[key])-c.maxBuffer:]
	}
	c.mu.Unlock()

	c.evaluateRules(key)
	return nil
}

func (c *Correlator) evaluateRules(orgID string) {
	c.mu.RLock()
	events := make([]core.Event, len(c.buffer[orgID]))
	copy(events, c.buffer[orgID])
	c.mu.RUnlock()

	now := time.Now()
	for _, rule := range c.rules {
		windowEvents := filterByWindow(events, now, rule.Window)
		if len(windowEvents) < rule.MinEvents {
			continue
		}

		if rule.Match(windowEvents) {
			result := CorrelationResult{
				Rule:      rule.Name,
				Events:    windowEvents,
				Severity:  rule.Severity,
				Category:  rule.Category,
				Summary:   rule.Description,
				Timestamp: now,
			}

			c.mu.Lock()
			c.results = append(c.results, result)
			c.mu.Unlock()

			select {
			case c.resultCh <- result:
			default:
			}
		}
	}
}

func filterByWindow(events []core.Event, now time.Time, window time.Duration) []core.Event {
	cutoff := now.Add(-window)
	var filtered []core.Event
	for _, e := range events {
		if e.Time.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (c *Correlator) Results() <-chan CorrelationResult {
	return c.resultCh
}

func (c *Correlator) GetResults() []CorrelationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]CorrelationResult, len(c.results))
	copy(result, c.results)
	return result
}

func (c *Correlator) ClearResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = nil
}

func (c *Correlator) RuleCount() int {
	return len(c.rules)
}

func (c *Correlator) registerDefaultRules() {
	c.RegisterRule(Rule{
		Name:        "brute_force_attack",
		Description: "Multiple authentication failures detected from same source",
		Window:      5 * time.Minute,
		MinEvents:   5,
		Severity:    "high",
		Category:    "attack",
		Match: func(events []core.Event) bool {
			failCount := 0
			for _, e := range events {
				if e.Category == "auth_failure" {
					failCount++
				}
			}
			return failCount >= 5
		},
	})

	c.RegisterRule(Rule{
		Name:        "port_scan_with_exploit",
		Description: "Port scanning followed by suspicious connection attempts",
		Window:      10 * time.Minute,
		MinEvents:   2,
		Severity:    "critical",
		Category:    "attack",
		Match: func(events []core.Event) bool {
			hasPortScan := false
			hasSuspicious := false
			for _, e := range events {
				if e.Category == "port_scan" {
					hasPortScan = true
				}
				if e.Category == "suspicious_port" {
					hasSuspicious = true
				}
			}
			return hasPortScan && hasSuspicious
		},
	})

	c.RegisterRule(Rule{
		Name:        "cloud_misconfiguration_chain",
		Description: "Multiple cloud misconfigurations detected in short window",
		Window:      30 * time.Minute,
		MinEvents:   3,
		Severity:    "high",
		Category:    "misconfiguration",
		Match: func(events []core.Event) bool {
			misconfigCount := 0
			for _, e := range events {
				if e.Source == "cloud" && e.Category == "misconfiguration" {
					misconfigCount++
				}
			}
			return misconfigCount >= 3
		},
	})

	c.RegisterRule(Rule{
		Name:        "lateral_movement",
		Description: "Auth failure followed by success from different source",
		Window:      15 * time.Minute,
		MinEvents:   2,
		Severity:    "critical",
		Category:    "attack",
		Match: func(events []core.Event) bool {
			hasFailure := false
			hasSuccess := false
			for _, e := range events {
				if e.Category == "auth_failure" {
					hasFailure = true
				}
				if e.Category == "auth_success" && hasFailure {
					hasSuccess = true
				}
			}
			return hasFailure && hasSuccess
		},
	})

	c.RegisterRule(Rule{
		Name:        "service_degradation",
		Description: "Multiple web errors indicating service degradation",
		Window:      5 * time.Minute,
		MinEvents:   10,
		Severity:    "medium",
		Category:    "availability",
		Match: func(events []core.Event) bool {
			errorCount := 0
			for _, e := range events {
				if e.Category == "web_error" {
					errorCount++
				}
			}
			return errorCount >= 10
		},
	})
}

func FormatResult(r CorrelationResult) string {
	return fmt.Sprintf("[%s] %s (%s): %s - %d correlated events",
		r.Severity, r.Rule, r.Category, r.Summary, len(r.Events))
}
