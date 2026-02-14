package core_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/engine/internal/core"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func setupTestNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{Port: -1}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("failed to create nats server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(ns.Shutdown)

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("failed to connect to nats: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func TestEngineStartStop(t *testing.T) {
	nc := setupTestNATS(t)
	engine := core.New(nc, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := engine.Stop(); err != nil {
		t.Fatalf("failed to stop engine: %v", err)
	}
}

func TestEnginePipelineExecution(t *testing.T) {
	nc := setupTestNATS(t)
	engine := core.New(nc, nil)

	processed := make(chan core.Event, 10)
	engine.RegisterPipeline("test", func(event core.Event) error {
		processed <- event
		return nil
	})

	if engine.PipelineCount() != 1 {
		t.Errorf("expected 1 pipeline, got %d", engine.PipelineCount())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	event := core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		AgentID:  "agent-1",
		Source:   "test",
		Category: "test_event",
		Severity: "info",
		Summary:  "test event",
	}

	data, _ := json.Marshal(event)
	nc.Publish("events.org-1.agent-1", data)

	select {
	case got := <-processed:
		if got.OrgID != "org-1" {
			t.Errorf("expected org_id 'org-1', got %s", got.OrgID)
		}
		if got.Category != "test_event" {
			t.Errorf("expected category 'test_event', got %s", got.Category)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for event processing")
	}

	engine.Stop()
}

func TestEngineMultiplePipelines(t *testing.T) {
	nc := setupTestNATS(t)
	engine := core.New(nc, nil)

	count1 := make(chan struct{}, 10)
	count2 := make(chan struct{}, 10)

	engine.RegisterPipeline("pipeline1", func(event core.Event) error {
		count1 <- struct{}{}
		return nil
	})
	engine.RegisterPipeline("pipeline2", func(event core.Event) error {
		count2 <- struct{}{}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)

	event := core.Event{
		Time:     time.Now(),
		OrgID:    "org-1",
		Source:   "test",
		Severity: "info",
	}
	data, _ := json.Marshal(event)
	nc.Publish("events.org-1.agent-1", data)

	select {
	case <-count1:
	case <-time.After(3 * time.Second):
		t.Error("pipeline1 timeout")
	}
	select {
	case <-count2:
	case <-time.After(3 * time.Second):
		t.Error("pipeline2 timeout")
	}

	engine.Stop()
}

func TestEngineProcessedCount(t *testing.T) {
	nc := setupTestNATS(t)
	engine := core.New(nc, nil)

	engine.RegisterPipeline("noop", func(event core.Event) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Start(ctx)

	for i := 0; i < 5; i++ {
		event := core.Event{
			Time:   time.Now(),
			OrgID:  "org-1",
			Source: "test",
		}
		data, _ := json.Marshal(event)
		nc.Publish("events.org-1.agent-1", data)
	}

	time.Sleep(500 * time.Millisecond)

	if engine.ProcessedCount() < 5 {
		t.Errorf("expected at least 5 processed, got %d", engine.ProcessedCount())
	}

	engine.Stop()
}
