package cloud

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

type Finding struct {
	Provider    Provider
	Resource    string
	ResourceID  string
	Category    string
	Severity    string
	Description string
	Remediation string
	Metadata    map[string]interface{}
}

type ScanRule struct {
	ID          string
	Provider    Provider
	Category    string
	Description string
	Check       func(ctx context.Context, client interface{}) ([]Finding, error)
}

type CloudCollector struct {
	provider   Provider
	scanners   []Scanner
	interval   time.Duration
	eventCh    chan<- core.Event
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	lastScan   time.Time
	findings   []Finding
}

type Scanner interface {
	Name() string
	Provider() Provider
	Scan(ctx context.Context) ([]Finding, error)
}

func NewCloudCollector(provider string, interval time.Duration) *CloudCollector {
	if interval == 0 {
		interval = 15 * time.Minute
	}
	c := &CloudCollector{
		provider: Provider(provider),
		interval: interval,
	}

	switch Provider(provider) {
	case ProviderAWS:
		c.scanners = append(c.scanners, NewAWSScanner())
	case ProviderAzure:
		c.scanners = append(c.scanners, NewAzureScanner())
	case ProviderGCP:
		c.scanners = append(c.scanners, NewGCPScanner())
	default:
		c.scanners = append(c.scanners, NewAWSScanner())
	}

	return c
}

func (c *CloudCollector) Name() string {
	return "cloud"
}

func (c *CloudCollector) Start(ctx context.Context, eventCh chan<- core.Event) error {
	ctx, c.cancel = context.WithCancel(ctx)
	c.eventCh = eventCh

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.scanLoop(ctx)
	}()

	c.wg.Wait()
	return nil
}

func (c *CloudCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	return nil
}

func (c *CloudCollector) scanLoop(ctx context.Context) {
	c.runScan(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.runScan(ctx)
		}
	}
}

func (c *CloudCollector) runScan(ctx context.Context) {
	log.Printf("cloud collector: starting %s scan", c.provider)

	var allFindings []Finding
	for _, scanner := range c.scanners {
		findings, err := scanner.Scan(ctx)
		if err != nil {
			log.Printf("cloud collector: scanner %s error: %v", scanner.Name(), err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	c.mu.Lock()
	c.findings = allFindings
	c.lastScan = time.Now()
	c.mu.Unlock()

	for _, f := range allFindings {
		event := findingToEvent(f)
		select {
		case c.eventCh <- event:
		default:
			log.Println("cloud collector: event channel full, dropping finding")
		}
	}

	log.Printf("cloud collector: scan complete, %d findings", len(allFindings))
}

func findingToEvent(f Finding) core.Event {
	return core.Event{
		Time:     time.Now(),
		Source:   "cloud",
		Category: f.Category,
		Severity: f.Severity,
		Summary:  f.Description,
		Payload: map[string]interface{}{
			"provider":    string(f.Provider),
			"resource":    f.Resource,
			"resource_id": f.ResourceID,
			"remediation": f.Remediation,
			"metadata":    f.Metadata,
		},
	}
}

func (c *CloudCollector) GetFindings() []Finding {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]Finding, len(c.findings))
	copy(result, c.findings)
	return result
}

func (c *CloudCollector) LastScanTime() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastScan
}

func (c *CloudCollector) RegisterScanner(s Scanner) {
	c.scanners = append(c.scanners, s)
}

func NewFinding(provider Provider, resource, resourceID, category, severity, description, remediation string) Finding {
	return Finding{
		Provider:    provider,
		Resource:    resource,
		ResourceID:  resourceID,
		Category:    category,
		Severity:    severity,
		Description: description,
		Remediation: remediation,
		Metadata:    make(map[string]interface{}),
	}
}

func FormatFinding(f Finding) string {
	return fmt.Sprintf("[%s] %s (%s): %s - %s",
		f.Severity, f.Provider, f.Resource, f.Description, f.Remediation)
}
