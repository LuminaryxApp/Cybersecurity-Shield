package cloud_test

import (
	"context"
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/collectors/cloud"
	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

type mockScanner struct {
	name     string
	provider cloud.Provider
	findings []cloud.Finding
	err      error
}

func (m *mockScanner) Name() string            { return m.name }
func (m *mockScanner) Provider() cloud.Provider { return m.provider }
func (m *mockScanner) Scan(ctx context.Context) ([]cloud.Finding, error) {
	return m.findings, m.err
}

func TestCloudCollectorName(t *testing.T) {
	c := cloud.NewCloudCollector("aws", 0)
	if c.Name() != "cloud" {
		t.Errorf("expected name 'cloud', got %s", c.Name())
	}
}

func TestCloudCollectorWithMockFindings(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := cloud.NewCloudCollector("aws", 1*time.Hour)

	mock := &mockScanner{
		name:     "test-scanner",
		provider: cloud.ProviderAWS,
		findings: []cloud.Finding{
			cloud.NewFinding(cloud.ProviderAWS, "s3", "test-bucket", "misconfiguration",
				"critical", "Test bucket is public", "Make it private"),
			cloud.NewFinding(cloud.ProviderAWS, "ec2-sg", "sg-123", "misconfiguration",
				"high", "Security group open to world", "Restrict access"),
		},
	}

	c.RegisterScanner(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)

	received := 0
	timeout := time.After(5 * time.Second)
	for received < 2 {
		select {
		case event := <-eventCh:
			if event.Source != "cloud" {
				t.Errorf("expected source 'cloud', got %s", event.Source)
			}
			received++
		case <-timeout:
			t.Fatalf("timeout waiting for events, got %d of 2", received)
		}
	}

	findings := c.GetFindings()
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}

	if c.LastScanTime().IsZero() {
		t.Error("expected last scan time to be set")
	}

	cancel()
}

func TestCloudCollectorEmptyScanner(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := cloud.NewCloudCollector("aws", 1*time.Hour)

	mock := &mockScanner{
		name:     "empty-scanner",
		provider: cloud.ProviderAWS,
		findings: nil,
	}

	c.RegisterScanner(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(500 * time.Millisecond)

	findings := c.GetFindings()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}

	cancel()
}

func TestNewFinding(t *testing.T) {
	f := cloud.NewFinding(cloud.ProviderAWS, "s3", "my-bucket", "misconfiguration",
		"critical", "Bucket is public", "Make it private")

	if f.Provider != cloud.ProviderAWS {
		t.Errorf("expected provider AWS, got %s", f.Provider)
	}
	if f.Resource != "s3" {
		t.Errorf("expected resource 's3', got %s", f.Resource)
	}
	if f.ResourceID != "my-bucket" {
		t.Errorf("expected resource ID 'my-bucket', got %s", f.ResourceID)
	}
	if f.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %s", f.Severity)
	}
	if f.Metadata == nil {
		t.Error("expected metadata to be initialized")
	}
}

func TestFormatFinding(t *testing.T) {
	f := cloud.NewFinding(cloud.ProviderAWS, "s3", "test-bucket", "misconfiguration",
		"high", "Bucket is public", "Restrict access")

	formatted := cloud.FormatFinding(f)
	if formatted == "" {
		t.Error("expected non-empty formatted string")
	}
}

func TestProviderConstants(t *testing.T) {
	if cloud.ProviderAWS != "aws" {
		t.Errorf("expected 'aws', got %s", cloud.ProviderAWS)
	}
	if cloud.ProviderAzure != "azure" {
		t.Errorf("expected 'azure', got %s", cloud.ProviderAzure)
	}
	if cloud.ProviderGCP != "gcp" {
		t.Errorf("expected 'gcp', got %s", cloud.ProviderGCP)
	}
}

func TestAWSScannerName(t *testing.T) {
	s := cloud.NewAWSScanner()
	if s.Name() != "aws" {
		t.Errorf("expected 'aws', got %s", s.Name())
	}
	if s.Provider() != cloud.ProviderAWS {
		t.Errorf("expected provider AWS, got %s", s.Provider())
	}
}

func TestAzureScannerName(t *testing.T) {
	s := cloud.NewAzureScanner()
	if s.Name() != "azure" {
		t.Errorf("expected 'azure', got %s", s.Name())
	}
	if s.Provider() != cloud.ProviderAzure {
		t.Errorf("expected provider Azure, got %s", s.Provider())
	}
}

func TestGCPScannerName(t *testing.T) {
	s := cloud.NewGCPScanner()
	if s.Name() != "gcp" {
		t.Errorf("expected 'gcp', got %s", s.Name())
	}
	if s.Provider() != cloud.ProviderGCP {
		t.Errorf("expected provider GCP, got %s", s.Provider())
	}
}

func TestAWSScannerSkipsWhenUnavailable(t *testing.T) {
	s := cloud.NewAWSScanner()
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when CLI unavailable, got %d", len(findings))
	}
}

func TestAzureScannerSkipsWhenUnavailable(t *testing.T) {
	s := cloud.NewAzureScanner()
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when CLI unavailable, got %d", len(findings))
	}
}

func TestGCPScannerSkipsWhenUnavailable(t *testing.T) {
	s := cloud.NewGCPScanner()
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when CLI unavailable, got %d", len(findings))
	}
}
