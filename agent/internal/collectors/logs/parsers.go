package logs

import (
	"regexp"
	"strings"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

var (
	nginxPattern = regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)`)
	authPattern  = regexp.MustCompile(`^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?: (.+)`)
)

func ParseSyslog(line string) core.Event {
	parts := strings.SplitN(line, " ", 4)
	severity := "info"

	if strings.Contains(strings.ToLower(line), "error") || strings.Contains(strings.ToLower(line), "fail") {
		severity = "medium"
	}
	if strings.Contains(strings.ToLower(line), "critical") || strings.Contains(strings.ToLower(line), "emergency") {
		severity = "critical"
	}

	summary := line
	if len(parts) >= 4 {
		summary = parts[3]
	}

	return core.Event{
		Time:     time.Now(),
		Source:   "syslog",
		Category: "system",
		Severity: severity,
		Summary:  truncate(summary, 500),
		Payload: map[string]interface{}{
			"raw": truncate(line, 2000),
		},
	}
}

func ParseNginxAccess(line string) core.Event {
	severity := "info"
	category := "web"
	payload := map[string]interface{}{"raw": truncate(line, 2000)}

	matches := nginxPattern.FindStringSubmatch(line)
	if len(matches) >= 8 {
		payload["remote_addr"] = matches[1]
		payload["method"] = matches[4]
		payload["path"] = matches[5]
		payload["status"] = matches[7]
		payload["bytes"] = matches[8]

		status := matches[7]
		if strings.HasPrefix(status, "4") {
			severity = "low"
			category = "web_error"
		}
		if strings.HasPrefix(status, "5") {
			severity = "medium"
			category = "web_error"
		}
	}

	return core.Event{
		Time:     time.Now(),
		Source:   "nginx",
		Category: category,
		Severity: severity,
		Summary:  truncate(line, 500),
		Payload:  payload,
	}
}

func ParseAuthLog(line string) core.Event {
	severity := "info"
	category := "auth"
	payload := map[string]interface{}{"raw": truncate(line, 2000)}

	matches := authPattern.FindStringSubmatch(line)
	if len(matches) >= 5 {
		payload["hostname"] = matches[2]
		payload["service"] = matches[3]
		payload["message"] = matches[4]
	}

	lower := strings.ToLower(line)
	if strings.Contains(lower, "failed") || strings.Contains(lower, "invalid") {
		severity = "medium"
		category = "auth_failure"
	}
	if strings.Contains(lower, "accepted") {
		severity = "info"
		category = "auth_success"
	}
	if strings.Contains(lower, "break-in") || strings.Contains(lower, "repeated") {
		severity = "high"
		category = "auth_brute_force"
	}

	return core.Event{
		Time:     time.Now(),
		Source:   "auth",
		Category: category,
		Severity: severity,
		Summary:  truncate(line, 500),
		Payload:  payload,
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
