package network_test

import (
	"context"
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/collectors/network"
	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

func TestNetworkCollectorName(t *testing.T) {
	c := network.NewNetworkCollector("eth0")
	if c.Name() != "network" {
		t.Errorf("expected name 'network', got %s", c.Name())
	}
}

func TestNetworkCollectorFlowTracking(t *testing.T) {
	c := network.NewNetworkCollector("eth0")

	key := network.FlowKey{
		SrcIP:    "192.168.1.10",
		DstIP:    "10.0.0.1",
		DstPort:  443,
		Protocol: "tcp",
	}

	now := time.Now()
	c.InjectFlow(key, &network.FlowStats{
		Key:       key,
		Packets:   50,
		Bytes:     4096,
		FirstSeen: now.Add(-5 * time.Minute),
		LastSeen:  now,
	})

	if c.FlowCount() != 1 {
		t.Errorf("expected 1 flow, got %d", c.FlowCount())
	}

	flows := c.GetFlows()
	flow, exists := flows[key]
	if !exists {
		t.Fatal("expected flow to exist")
	}
	if flow.Packets != 50 {
		t.Errorf("expected 50 packets, got %d", flow.Packets)
	}
}

func TestNetworkCollectorPortScanDetection(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := network.NewNetworkCollector("eth0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(100 * time.Millisecond)

	now := time.Now()
	for i := 1; i <= 25; i++ {
		key := network.FlowKey{
			SrcIP:    "10.0.0.99",
			DstIP:    "192.168.1.1",
			DstPort:  i * 100,
			Protocol: "tcp",
		}
		c.InjectFlow(key, &network.FlowStats{
			Key:       key,
			Packets:   1,
			Bytes:     64,
			FirstSeen: now,
			LastSeen:  now,
		})
	}

	var portScanEvent *core.Event
	timeout := time.After(20 * time.Second)
	for {
		select {
		case event := <-eventCh:
			if event.Category == "port_scan" {
				portScanEvent = &event
			}
		case <-timeout:
			if portScanEvent == nil {
				t.Error("timeout waiting for port scan event")
			}
			cancel()
			return
		}
		if portScanEvent != nil {
			break
		}
	}

	if portScanEvent.Source != "network" {
		t.Errorf("expected source 'network', got %s", portScanEvent.Source)
	}
	if portScanEvent.Severity != "high" {
		t.Errorf("expected severity 'high', got %s", portScanEvent.Severity)
	}
	cancel()
}

func TestNetworkCollectorSuspiciousPort(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := network.NewNetworkCollector("eth0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(100 * time.Millisecond)

	now := time.Now()
	key := network.FlowKey{
		SrcIP:    "192.168.1.5",
		DstIP:    "evil.server.com",
		DstPort:  4444,
		Protocol: "tcp",
	}
	c.InjectFlow(key, &network.FlowStats{
		Key:       key,
		Packets:   5,
		Bytes:     256,
		FirstSeen: now,
		LastSeen:  now,
	})

	var suspiciousEvent *core.Event
	timeout := time.After(35 * time.Second)
	for {
		select {
		case event := <-eventCh:
			if event.Category == "suspicious_port" {
				suspiciousEvent = &event
			}
		case <-timeout:
			if suspiciousEvent == nil {
				t.Error("timeout waiting for suspicious port event")
			}
			cancel()
			return
		}
		if suspiciousEvent != nil {
			break
		}
	}

	if suspiciousEvent.Severity != "high" {
		t.Errorf("expected severity 'high', got %s", suspiciousEvent.Severity)
	}
	cancel()
}

func TestNetworkCollectorHighTraffic(t *testing.T) {
	eventCh := make(chan core.Event, 100)
	c := network.NewNetworkCollector("eth0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Start(ctx, eventCh)
	time.Sleep(100 * time.Millisecond)

	now := time.Now()
	key := network.FlowKey{
		SrcIP:    "192.168.1.10",
		DstIP:    "10.0.0.5",
		DstPort:  80,
		Protocol: "tcp",
	}
	c.InjectFlow(key, &network.FlowStats{
		Key:       key,
		Packets:   150,
		Bytes:     1048576,
		FirstSeen: now.Add(-2 * time.Minute),
		LastSeen:  now,
	})

	var highTrafficEvent *core.Event
	timeout := time.After(35 * time.Second)
	for {
		select {
		case event := <-eventCh:
			if event.Category == "high_traffic" {
				highTrafficEvent = &event
			}
		case <-timeout:
			if highTrafficEvent == nil {
				t.Error("timeout waiting for high traffic event")
			}
			cancel()
			return
		}
		if highTrafficEvent != nil {
			break
		}
	}

	if highTrafficEvent.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %s", highTrafficEvent.Severity)
	}
	cancel()
}

func TestParseNetstatOutput(t *testing.T) {
	conn := network.FormatConnection(network.ConnectionInfo{
		LocalAddr:  "192.168.1.10",
		RemoteAddr: "10.0.0.1",
		LocalPort:  12345,
		RemotePort: 443,
		Protocol:   "tcp",
		State:      "ESTABLISHED",
	})

	expected := "tcp 192.168.1.10:12345 -> 10.0.0.1:443 [ESTABLISHED]"
	if conn != expected {
		t.Errorf("expected %q, got %q", expected, conn)
	}
}
