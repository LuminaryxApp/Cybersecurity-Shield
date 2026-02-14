package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

type mockCollector struct {
	name    string
	started bool
	stopped bool
}

func (m *mockCollector) Name() string { return m.name }
func (m *mockCollector) Start(ctx context.Context, eventCh chan<- core.Event) error {
	m.started = true
	eventCh <- core.Event{
		Source:   "mock",
		Category: "test",
		Severity: "low",
		Summary:  "test event from " + m.name,
	}
	<-ctx.Done()
	return nil
}
func (m *mockCollector) Stop() error {
	m.stopped = true
	return nil
}

func TestAgentRegistersCollectors(t *testing.T) {
	agent := core.New("test-agent", "test-org", "http://localhost:8080", nil, 30)

	c1 := &mockCollector{name: "logs"}
	c2 := &mockCollector{name: "network"}
	agent.Register(c1)
	agent.Register(c2)

	if agent.CollectorCount() != 2 {
		t.Errorf("expected 2 collectors, got %d", agent.CollectorCount())
	}
}

func TestAgentStartAndStop(t *testing.T) {
	agent := core.New("test-agent", "test-org", "http://localhost:8080", nil, 30)

	mock := &mockCollector{name: "test"}
	agent.Register(mock)

	ctx := context.Background()
	err := agent.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start agent: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if !mock.started {
		t.Error("expected collector to be started")
	}

	err = agent.Stop()
	if err != nil {
		t.Fatalf("failed to stop agent: %v", err)
	}

	if !mock.stopped {
		t.Error("expected collector to be stopped")
	}
}

func TestAgentForwardsEvents(t *testing.T) {
	agent := core.New("test-agent", "test-org", "http://localhost:8080", nil, 30)

	mock := &mockCollector{name: "forwarder-test"}
	agent.Register(mock)

	ctx := context.Background()
	agent.Start(ctx)

	time.Sleep(200 * time.Millisecond)

	agent.Stop()
}
