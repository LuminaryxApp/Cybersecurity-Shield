package scoring

import (
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
)

type ThreatScore struct {
	Score   float64                `json:"score"`
	Trend   float64                `json:"trend"`
	Factors map[string]float64     `json:"factors"`
	Updated time.Time              `json:"updated"`
}

type EventScore struct {
	Event     core.Event
	RiskScore float64
}

type SeverityWeight struct {
	Info     float64
	Low      float64
	Medium   float64
	High     float64
	Critical float64
}

var DefaultWeights = SeverityWeight{
	Info:     0.0,
	Low:      1.0,
	Medium:   3.0,
	High:     7.0,
	Critical: 10.0,
}

type CategoryMultiplier struct {
	Attack           float64
	Misconfiguration float64
	AuthFailure      float64
	Availability     float64
	CredentialHygiene float64
	Default          float64
}

var DefaultMultipliers = CategoryMultiplier{
	Attack:           2.0,
	Misconfiguration: 1.5,
	AuthFailure:      1.3,
	Availability:     1.0,
	CredentialHygiene: 1.2,
	Default:          1.0,
}

type Scorer struct {
	mu           sync.RWMutex
	weights      SeverityWeight
	multipliers  CategoryMultiplier
	orgScores    map[string]*ThreatScore
	decayRate    float64
	window       time.Duration
	eventScores  map[string][]EventScore
}

func New(window time.Duration) *Scorer {
	if window == 0 {
		window = 24 * time.Hour
	}
	return &Scorer{
		weights:     DefaultWeights,
		multipliers: DefaultMultipliers,
		orgScores:   make(map[string]*ThreatScore),
		eventScores: make(map[string][]EventScore),
		decayRate:   0.95,
		window:      window,
	}
}

func (s *Scorer) ScoreEvent(event core.Event) float64 {
	base := s.severityScore(event.Severity)
	multiplier := s.categoryMultiplier(event.Category)

	recencyFactor := 1.0
	if !event.Time.IsZero() {
		age := time.Since(event.Time)
		recencyFactor = math.Pow(s.decayRate, age.Hours())
	}

	return base * multiplier * recencyFactor
}

func (s *Scorer) Process(event core.Event) error {
	score := s.ScoreEvent(event)

	s.mu.Lock()
	defer s.mu.Unlock()

	orgID := event.OrgID
	if orgID == "" {
		orgID = "default"
	}

	s.eventScores[orgID] = append(s.eventScores[orgID], EventScore{
		Event:     event,
		RiskScore: score,
	})

	cutoff := time.Now().Add(-s.window)
	filtered := make([]EventScore, 0)
	for _, es := range s.eventScores[orgID] {
		if es.Event.Time.After(cutoff) {
			filtered = append(filtered, es)
		}
	}
	s.eventScores[orgID] = filtered

	s.recalculateThreatScore(orgID)
	return nil
}

func (s *Scorer) recalculateThreatScore(orgID string) {
	events := s.eventScores[orgID]
	if len(events) == 0 {
		s.orgScores[orgID] = &ThreatScore{
			Score:   100.0,
			Trend:   0.0,
			Factors: make(map[string]float64),
			Updated: time.Now(),
		}
		return
	}

	factors := make(map[string]float64)
	totalPenalty := 0.0

	for _, es := range events {
		cat := es.Event.Category
		if cat == "" {
			cat = "unknown"
		}
		factors[cat] += es.RiskScore
		totalPenalty += es.RiskScore
	}

	maxPenalty := 100.0
	if totalPenalty > maxPenalty {
		totalPenalty = maxPenalty
	}

	score := 100.0 - totalPenalty

	if score < 0 {
		score = 0
	}

	var trend float64
	prev, exists := s.orgScores[orgID]
	if exists {
		trend = score - prev.Score
	}

	for k, v := range factors {
		factors[k] = math.Round(v*100) / 100
	}

	s.orgScores[orgID] = &ThreatScore{
		Score:   math.Round(score*100) / 100,
		Trend:   math.Round(trend*100) / 100,
		Factors: factors,
		Updated: time.Now(),
	}
}

func (s *Scorer) GetThreatScore(orgID string) *ThreatScore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ts, exists := s.orgScores[orgID]; exists {
		copy := *ts
		factors := make(map[string]float64)
		for k, v := range ts.Factors {
			factors[k] = v
		}
		copy.Factors = factors
		return &copy
	}
	return &ThreatScore{
		Score:   100.0,
		Trend:   0.0,
		Factors: make(map[string]float64),
		Updated: time.Now(),
	}
}

func (s *Scorer) GetThreatScoreJSON(orgID string) ([]byte, error) {
	ts := s.GetThreatScore(orgID)
	return json.Marshal(ts)
}

func (s *Scorer) severityScore(severity string) float64 {
	switch severity {
	case "info":
		return s.weights.Info
	case "low":
		return s.weights.Low
	case "medium":
		return s.weights.Medium
	case "high":
		return s.weights.High
	case "critical":
		return s.weights.Critical
	default:
		return s.weights.Low
	}
}

func (s *Scorer) categoryMultiplier(category string) float64 {
	switch category {
	case "attack", "port_scan", "auth_brute_force":
		return s.multipliers.Attack
	case "misconfiguration":
		return s.multipliers.Misconfiguration
	case "auth_failure":
		return s.multipliers.AuthFailure
	case "availability", "web_error":
		return s.multipliers.Availability
	case "credential_hygiene":
		return s.multipliers.CredentialHygiene
	default:
		return s.multipliers.Default
	}
}

func (s *Scorer) OrgCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.orgScores)
}
