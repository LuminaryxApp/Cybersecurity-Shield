package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type LLMProvider interface {
	Explain(ctx context.Context, event Event, context string) (string, error)
	Summarize(ctx context.Context, events []Event) (string, error)
}

type AnthropicProvider struct {
	apiKey string
	model  string
	client *http.Client
}

func NewAnthropicProvider(apiKey, model string) *AnthropicProvider {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &AnthropicProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (p *AnthropicProvider) Explain(ctx context.Context, event Event, eventContext string) (string, error) {
	if p.apiKey == "" {
		return generateLocalExplanation(event), nil
	}

	prompt := fmt.Sprintf(`You are a cybersecurity analyst. Analyze this security event and provide a brief, actionable explanation suitable for both technical and non-technical audiences.

Event Details:
- Source: %s
- Category: %s
- Severity: %s
- Summary: %s
- Risk Score: %.1f

Additional Context: %s

Provide:
1. What happened (1-2 sentences, plain language)
2. Why it matters (1-2 sentences)
3. Recommended action (1-2 sentences)

Keep your response concise and focused.`, event.Source, event.Category, event.Severity, event.Summary, event.RiskScore, eventContext)

	return p.call(ctx, prompt)
}

func (p *AnthropicProvider) Summarize(ctx context.Context, events []Event) (string, error) {
	if p.apiKey == "" {
		return generateLocalSummary(events), nil
	}

	eventDescriptions := ""
	for i, e := range events {
		if i >= 20 {
			eventDescriptions += fmt.Sprintf("\n... and %d more events", len(events)-20)
			break
		}
		eventDescriptions += fmt.Sprintf("\n- [%s] %s: %s (severity: %s)", e.Source, e.Category, e.Summary, e.Severity)
	}

	prompt := fmt.Sprintf(`You are a cybersecurity analyst. Summarize these %d security events into a brief executive summary suitable for a business owner.

Events:%s

Provide:
1. Overall threat assessment (1 sentence)
2. Key findings (2-3 bullet points)
3. Priority actions (2-3 bullet points)

Keep it concise and actionable.`, len(events), eventDescriptions)

	return p.call(ctx, prompt)
}

func (p *AnthropicProvider) call(ctx context.Context, prompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 500,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result anthropicResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return result.Content[0].Text, nil
}

func generateLocalExplanation(event Event) string {
	var explanation string

	switch event.Category {
	case "auth_failure":
		explanation = fmt.Sprintf("A failed authentication attempt was detected from %s. "+
			"This could indicate a brute force attack or unauthorized access attempt. "+
			"Monitor for repeated failures and consider implementing rate limiting.", event.Source)
	case "auth_brute_force":
		explanation = fmt.Sprintf("Multiple repeated authentication failures detected, suggesting a brute force attack. "+
			"This is a %s severity event. "+
			"Immediately review access logs, block the source IP, and consider enabling account lockout policies.", event.Severity)
	case "port_scan":
		explanation = "Port scanning activity detected, which is often a precursor to an attack. " +
			"An external entity is probing your network for open services. " +
			"Review firewall rules and ensure only necessary ports are exposed."
	case "suspicious_port":
		explanation = "A connection to a port commonly associated with malicious activity was detected. " +
			"This may indicate malware communication or a compromised system. " +
			"Investigate the source system immediately and check for malware."
	case "misconfiguration":
		explanation = fmt.Sprintf("A cloud resource misconfiguration was found in %s. "+
			"Misconfigurations are a leading cause of data breaches. "+
			"Review and remediate the identified issue promptly.", event.Source)
	case "web_error":
		explanation = "Multiple web server errors detected, indicating potential service degradation. " +
			"This could be caused by an attack, misconfiguration, or resource exhaustion. " +
			"Check server logs and resource utilization."
	case "high_traffic":
		explanation = "Unusually high network traffic volume detected. " +
			"This could indicate a DDoS attack, data exfiltration, or legitimate traffic spike. " +
			"Monitor traffic patterns and investigate the source."
	default:
		explanation = fmt.Sprintf("Security event detected: %s (category: %s, severity: %s). "+
			"Review the event details and take appropriate action based on your security policies.",
			event.Summary, event.Category, event.Severity)
	}

	return explanation
}

func generateLocalSummary(events []Event) string {
	if len(events) == 0 {
		return "No security events to summarize."
	}

	severityCounts := make(map[string]int)
	categoryCounts := make(map[string]int)

	for _, e := range events {
		severityCounts[e.Severity]++
		categoryCounts[e.Category]++
	}

	summary := fmt.Sprintf("Security Summary: %d events detected. ", len(events))

	if severityCounts["critical"] > 0 {
		summary += fmt.Sprintf("%d critical events require immediate attention. ", severityCounts["critical"])
	}
	if severityCounts["high"] > 0 {
		summary += fmt.Sprintf("%d high severity events should be investigated. ", severityCounts["high"])
	}

	summary += "Categories: "
	for cat, count := range categoryCounts {
		summary += fmt.Sprintf("%s (%d), ", cat, count)
	}

	return summary
}
