package messaging_test

import (
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/messaging"
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

func TestPublishAndSubscribe(t *testing.T) {
	nc := setupTestNATS(t)
	bus := messaging.New(nc)

	received := make(chan []byte, 1)
	err := bus.Subscribe("test.subject", func(data []byte) {
		received <- data
	})
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}

	err = bus.Publish("test.subject", []byte(`{"test":"data"}`))
	if err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	select {
	case msg := <-received:
		if string(msg) != `{"test":"data"}` {
			t.Errorf("unexpected message: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for message")
	}
}

func TestMultipleSubscribers(t *testing.T) {
	nc := setupTestNATS(t)
	bus := messaging.New(nc)

	count := make(chan struct{}, 2)

	bus.Subscribe("multi.test", func(data []byte) {
		count <- struct{}{}
	})
	bus.Subscribe("multi.test", func(data []byte) {
		count <- struct{}{}
	})

	bus.Publish("multi.test", []byte(`{"hello":"world"}`))

	received := 0
	timeout := time.After(2 * time.Second)
	for received < 2 {
		select {
		case <-count:
			received++
		case <-timeout:
			t.Fatalf("expected 2 messages, got %d", received)
		}
	}
}
