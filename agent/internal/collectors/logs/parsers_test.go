package logs_test

import (
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/collectors/logs"
)

func TestParseSyslogNormal(t *testing.T) {
	line := "Jan 14 12:00:00 server1 systemd[1]: Started Daily apt download activities."
	event := logs.ParseSyslog(line)

	if event.Source != "syslog" {
		t.Errorf("expected source 'syslog', got %s", event.Source)
	}
	if event.Severity != "info" {
		t.Errorf("expected severity 'info', got %s", event.Severity)
	}
}

func TestParseSyslogError(t *testing.T) {
	line := "Jan 14 12:00:00 server1 kernel: error: disk read failure on sda1"
	event := logs.ParseSyslog(line)

	if event.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %s", event.Severity)
	}
}

func TestParseSyslogCritical(t *testing.T) {
	line := "Jan 14 12:00:00 server1 kernel: critical: filesystem corruption detected"
	event := logs.ParseSyslog(line)

	if event.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %s", event.Severity)
	}
}

func TestParseNginxAccess200(t *testing.T) {
	line := `192.168.1.1 - - [14/Jan/2026:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 16`
	event := logs.ParseNginxAccess(line)

	if event.Source != "nginx" {
		t.Errorf("expected source 'nginx', got %s", event.Source)
	}
	if event.Severity != "info" {
		t.Errorf("expected severity 'info', got %s", event.Severity)
	}
	if event.Payload["remote_addr"] != "192.168.1.1" {
		t.Errorf("expected remote_addr '192.168.1.1', got %v", event.Payload["remote_addr"])
	}
	if event.Payload["method"] != "GET" {
		t.Errorf("expected method 'GET', got %v", event.Payload["method"])
	}
}

func TestParseNginxAccess500(t *testing.T) {
	line := `10.0.0.5 - - [14/Jan/2026:12:00:00 +0000] "POST /api/data HTTP/1.1" 500 0`
	event := logs.ParseNginxAccess(line)

	if event.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %s", event.Severity)
	}
	if event.Category != "web_error" {
		t.Errorf("expected category 'web_error', got %s", event.Category)
	}
}

func TestParseAuthLogFailure(t *testing.T) {
	line := "Jan 14 12:00:00 server1 sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
	event := logs.ParseAuthLog(line)

	if event.Source != "auth" {
		t.Errorf("expected source 'auth', got %s", event.Source)
	}
	if event.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %s", event.Severity)
	}
	if event.Category != "auth_failure" {
		t.Errorf("expected category 'auth_failure', got %s", event.Category)
	}
}

func TestParseAuthLogSuccess(t *testing.T) {
	line := "Jan 14 12:00:00 server1 sshd[1234]: Accepted publickey for admin from 10.0.0.2 port 22 ssh2"
	event := logs.ParseAuthLog(line)

	if event.Severity != "info" {
		t.Errorf("expected severity 'info', got %s", event.Severity)
	}
	if event.Category != "auth_success" {
		t.Errorf("expected category 'auth_success', got %s", event.Category)
	}
}

func TestParseAuthLogBruteForce(t *testing.T) {
	line := "Jan 14 12:00:00 server1 sshd[1234]: message repeated 5 times: Failed password for root"
	event := logs.ParseAuthLog(line)

	if event.Severity != "high" {
		t.Errorf("expected severity 'high', got %s", event.Severity)
	}
	if event.Category != "auth_brute_force" {
		t.Errorf("expected category 'auth_brute_force', got %s", event.Category)
	}
}
