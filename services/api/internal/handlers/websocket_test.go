package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/services/api/internal/handlers"
	"github.com/gorilla/websocket"
)

func TestWSHubBroadcast(t *testing.T) {
	hub := handlers.NewWSHub()
	server := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to connect ws client 1: %v", err)
	}
	defer conn1.Close()

	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to connect ws client 2: %v", err)
	}
	defer conn2.Close()

	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 2 {
		t.Errorf("expected 2 clients, got %d", hub.ClientCount())
	}

	hub.Broadcast([]byte(`{"type":"alert","data":"test"}`))

	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg1, err := conn1.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read from client 1: %v", err)
	}
	if string(msg1) != `{"type":"alert","data":"test"}` {
		t.Errorf("unexpected message on client 1: %s", msg1)
	}

	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg2, err := conn2.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read from client 2: %v", err)
	}
	if string(msg2) != `{"type":"alert","data":"test"}` {
		t.Errorf("unexpected message on client 2: %s", msg2)
	}
}

func TestWSHubClientDisconnect(t *testing.T) {
	hub := handlers.NewWSHub()
	server := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", hub.ClientCount())
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)

	hub.Broadcast([]byte(`{"test":"cleanup"}`))
	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 0 {
		t.Errorf("expected 0 clients after disconnect, got %d", hub.ClientCount())
	}
}
