package logs_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/collectors/logs"
	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

func TestLogCollectorName(t *testing.T) {
	c := logs.NewLogCollector(nil, "")
	if c.Name() != "logs" {
		t.Errorf("expected name 'logs', got %s", c.Name())
	}
}

func TestLogCollectorSyslog(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := logs.NewLogCollector([]string{"syslog://:0"}, ":0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(200 * time.Millisecond)

	addr := c.SyslogAddr()
	if addr == "" {
		t.Fatal("syslog listener did not start")
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to connect to syslog: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Jan 14 12:00:00 testhost kernel: error: test disk failure"))
	if err != nil {
		t.Fatalf("failed to send syslog message: %v", err)
	}

	select {
	case event := <-eventCh:
		if event.Source != "syslog" {
			t.Errorf("expected source 'syslog', got %s", event.Source)
		}
		if event.Severity != "medium" {
			t.Errorf("expected severity 'medium', got %s", event.Severity)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for syslog event")
	}

	cancel()
}

func TestLogCollectorFileTail(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test-auth.log")

	f, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("failed to create temp log file: %v", err)
	}

	eventCh := make(chan core.Event, 100)
	c := logs.NewLogCollector([]string{"file://" + logFile}, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(200 * time.Millisecond)

	_, err = f.WriteString("Jan 14 12:00:00 server1 sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n")
	if err != nil {
		t.Fatalf("failed to write to log file: %v", err)
	}
	f.Sync()

	select {
	case event := <-eventCh:
		if event.Source != "auth" {
			t.Errorf("expected source 'auth', got %s", event.Source)
		}
		if event.Category != "auth_failure" {
			t.Errorf("expected category 'auth_failure', got %s", event.Category)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for file tail event")
	}

	f.Close()
	cancel()
}

func TestLogCollectorDefaultSyslog(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := logs.NewLogCollector(nil, ":0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(200 * time.Millisecond)

	addr := c.SyslogAddr()
	if addr == "" {
		t.Fatal("default syslog listener did not start")
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to connect to syslog: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Jan 14 12:00:00 testhost systemd[1]: Started Daily apt tasks."))
	if err != nil {
		t.Fatalf("failed to send syslog message: %v", err)
	}

	select {
	case event := <-eventCh:
		if event.Severity != "info" {
			t.Errorf("expected severity 'info', got %s", event.Severity)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for default syslog event")
	}

	cancel()
}

func TestDetectParserFromPath(t *testing.T) {
	eventCh := make(chan core.Event, 100)

	tmpDir := t.TempDir()
	nginxLog := filepath.Join(tmpDir, "nginx-access.log")

	f, err := os.Create(nginxLog)
	if err != nil {
		t.Fatalf("failed to create nginx log: %v", err)
	}

	c := logs.NewLogCollector([]string{"file://" + nginxLog}, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(200 * time.Millisecond)

	_, err = f.WriteString(`192.168.1.1 - - [14/Jan/2026:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 16` + "\n")
	if err != nil {
		t.Fatalf("failed to write to nginx log: %v", err)
	}
	f.Sync()

	select {
	case event := <-eventCh:
		if event.Source != "nginx" {
			t.Errorf("expected source 'nginx', got %s", event.Source)
		}
		if event.Payload["method"] != "GET" {
			t.Errorf("expected method 'GET', got %v", event.Payload["method"])
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for nginx access event")
	}

	f.Close()
	cancel()
}

func TestFormatSource(t *testing.T) {
	s := logs.FormatSource("syslog", ":1514")
	if s != "syslog://:1514" {
		t.Errorf("expected 'syslog://:1514', got %s", s)
	}

	s = logs.FormatSource("file", "/var/log/syslog")
	if s != "file:///var/log/syslog" {
		t.Errorf("expected 'file:///var/log/syslog', got %s", s)
	}
}
