package scoring_test

import (
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/scoring"
)

func TestScorerCreation(t *testing.T) {
	s := scoring.New(0)
	if s == nil {
		t.Fatal("expected non-nil scorer")
	}
}

func TestScoreEventSeverity(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	tests := []struct {
		severity string
		minScore float64
	}{
		{"info", 0},
		{"low", 0.5},
		{"medium", 1.0},
		{"high", 5.0},
		{"critical", 8.0},
	}

	for _, tt := range tests {
		event := core.Event{
			Time:     time.Now(),
			Severity: tt.severity,
			Category: "system",
		}
		score := s.ScoreEvent(event)
		if score < tt.minScore {
			t.Errorf("severity %s: expected score >= %f, got %f", tt.severity, tt.minScore, score)
		}
	}
}

func TestScoreEventCategory(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	attackEvent := core.Event{
		Time:     time.Now(),
		Severity: "high",
		Category: "attack",
	}
	normalEvent := core.Event{
		Time:     time.Now(),
		Severity: "high",
		Category: "system",
	}

	attackScore := s.ScoreEvent(attackEvent)
	normalScore := s.ScoreEvent(normalEvent)

	if attackScore <= normalScore {
		t.Errorf("attack score (%f) should be higher than normal (%f)", attackScore, normalScore)
	}
}

func TestThreatScoreDefault(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	ts := s.GetThreatScore("nonexistent-org")
	if ts.Score != 100.0 {
		t.Errorf("expected default score 100.0, got %f", ts.Score)
	}
	if ts.Trend != 0.0 {
		t.Errorf("expected default trend 0.0, got %f", ts.Trend)
	}
}

func TestThreatScoreDecreasesWithEvents(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	for i := 0; i < 5; i++ {
		s.Process(core.Event{
			Time:     time.Now(),
			OrgID:    "org-1",
			Source:   "auth",
			Category: "auth_failure",
			Severity: "medium",
		})
	}

	ts := s.GetThreatScore("org-1")
	if ts.Score >= 100.0 {
		t.Errorf("expected score below 100 after events, got %f", ts.Score)
	}
}

func TestThreatScoreCriticalEvents(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Source:   "cloud",
		Category: "attack",
		Severity: "critical",
	})

	ts := s.GetThreatScore("org-1")
	if ts.Score >= 90.0 {
		t.Errorf("expected significant score drop after critical attack, got %f", ts.Score)
	}
}

func TestThreatScoreFactors(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "auth_failure",
		Severity: "medium",
	})
	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "misconfiguration",
		Severity: "high",
	})

	ts := s.GetThreatScore("org-1")
	if len(ts.Factors) < 2 {
		t.Errorf("expected at least 2 factors, got %d", len(ts.Factors))
	}

	if _, exists := ts.Factors["auth_failure"]; !exists {
		t.Error("expected auth_failure factor")
	}
	if _, exists := ts.Factors["misconfiguration"]; !exists {
		t.Error("expected misconfiguration factor")
	}
}

func TestThreatScoreTrend(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "auth_failure",
		Severity: "medium",
	})

	ts1 := s.GetThreatScore("org-1")

	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "attack",
		Severity: "critical",
	})

	ts2 := s.GetThreatScore("org-1")
	if ts2.Score >= ts1.Score {
		t.Error("expected score to decrease after critical attack")
	}
}

func TestThreatScoreJSON(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "auth_failure",
		Severity: "medium",
	})

	data, err := s.GetThreatScoreJSON("org-1")
	if err != nil {
		t.Fatalf("failed to get JSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestScorerMultipleOrgs(t *testing.T) {
	s := scoring.New(24 * time.Hour)

	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Category: "attack",
		Severity: "critical",
	})
	s.Process(core.Event{
		Time:     time.Now(),
		OrgID:    "org-2",
		Category: "system",
		Severity: "info",
	})

	ts1 := s.GetThreatScore("org-1")
	ts2 := s.GetThreatScore("org-2")

	if ts1.Score >= ts2.Score {
		t.Errorf("org-1 (attack) should have lower score than org-2 (info): %f vs %f", ts1.Score, ts2.Score)
	}

	if s.OrgCount() != 2 {
		t.Errorf("expected 2 orgs, got %d", s.OrgCount())
	}
}
