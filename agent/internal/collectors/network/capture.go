package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

type FlowKey struct {
	SrcIP    string
	DstIP    string
	DstPort  int
	Protocol string
}

type FlowStats struct {
	Key       FlowKey
	Packets   int64
	Bytes     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

type NetworkCollector struct {
	iface      string
	eventCh    chan<- core.Event
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	flows      map[FlowKey]*FlowStats
	listenPort int
	listener   net.Listener
}

func NewNetworkCollector(iface string) *NetworkCollector {
	return &NetworkCollector{
		iface: iface,
		flows: make(map[FlowKey]*FlowStats),
	}
}

func (c *NetworkCollector) Name() string {
	return "network"
}

func (c *NetworkCollector) Start(ctx context.Context, eventCh chan<- core.Event) error {
	ctx, c.cancel = context.WithCancel(ctx)
	c.eventCh = eventCh

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.monitorConnections(ctx)
	}()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.flowAnalyzer(ctx)
	}()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.portScanDetector(ctx)
	}()

	c.wg.Wait()
	return nil
}

func (c *NetworkCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.listener != nil {
		c.listener.Close()
	}
	c.wg.Wait()
	return nil
}

func (c *NetworkCollector) monitorConnections(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Printf("network collector: monitoring connections on interface %s", c.iface)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			connections := c.getActiveConnections()
			for _, conn := range connections {
				c.recordFlow(conn)
			}
		}
	}
}

type ConnectionInfo struct {
	LocalAddr  string
	RemoteAddr string
	LocalPort  int
	RemotePort int
	Protocol   string
	State      string
}

func (c *NetworkCollector) getActiveConnections() []ConnectionInfo {
	return getSystemConnections()
}

func (c *NetworkCollector) recordFlow(conn ConnectionInfo) {
	key := FlowKey{
		SrcIP:    conn.LocalAddr,
		DstIP:    conn.RemoteAddr,
		DstPort:  conn.RemotePort,
		Protocol: conn.Protocol,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if flow, exists := c.flows[key]; exists {
		flow.Packets++
		flow.LastSeen = now
	} else {
		c.flows[key] = &FlowStats{
			Key:       key,
			Packets:   1,
			Bytes:     0,
			FirstSeen: now,
			LastSeen:  now,
		}
	}
}

func (c *NetworkCollector) flowAnalyzer(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.analyzeFlows()
		}
	}
}

func (c *NetworkCollector) analyzeFlows() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	staleThreshold := now.Add(-5 * time.Minute)

	for key, flow := range c.flows {
		if flow.LastSeen.Before(staleThreshold) {
			delete(c.flows, key)
			continue
		}

		if flow.Packets > 100 {
			event := core.Event{
				Time:     now,
				Source:   "network",
				Category: "high_traffic",
				Severity: "medium",
				Summary:  fmt.Sprintf("High traffic flow: %s -> %s:%d (%d packets)", key.SrcIP, key.DstIP, key.DstPort, flow.Packets),
				Payload: map[string]interface{}{
					"src_ip":    key.SrcIP,
					"dst_ip":    key.DstIP,
					"dst_port":  key.DstPort,
					"protocol":  key.Protocol,
					"packets":   flow.Packets,
					"bytes":     flow.Bytes,
					"duration":  flow.LastSeen.Sub(flow.FirstSeen).Seconds(),
				},
			}
			c.emitEvent(event)
		}

		if isKnownMaliciousPort(key.DstPort) {
			event := core.Event{
				Time:     now,
				Source:   "network",
				Category: "suspicious_port",
				Severity: "high",
				Summary:  fmt.Sprintf("Connection to suspicious port: %s -> %s:%d", key.SrcIP, key.DstIP, key.DstPort),
				Payload: map[string]interface{}{
					"src_ip":   key.SrcIP,
					"dst_ip":   key.DstIP,
					"dst_port": key.DstPort,
					"protocol": key.Protocol,
				},
			}
			c.emitEvent(event)
		}
	}
}

func (c *NetworkCollector) portScanDetector(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.detectPortScans()
		}
	}
}

func (c *NetworkCollector) detectPortScans() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	portsBySource := make(map[string]map[int]bool)

	for key := range c.flows {
		if _, exists := portsBySource[key.SrcIP]; !exists {
			portsBySource[key.SrcIP] = make(map[int]bool)
		}
		portsBySource[key.SrcIP][key.DstPort] = true
	}

	for srcIP, ports := range portsBySource {
		if len(ports) > 20 {
			portList := make([]int, 0, len(ports))
			for p := range ports {
				portList = append(portList, p)
			}

			event := core.Event{
				Time:     time.Now(),
				Source:   "network",
				Category: "port_scan",
				Severity: "high",
				Summary:  fmt.Sprintf("Potential port scan from %s: %d unique ports contacted", srcIP, len(ports)),
				Payload: map[string]interface{}{
					"src_ip":      srcIP,
					"unique_ports": len(ports),
					"sample_ports": portList[:min(10, len(portList))],
				},
			}
			c.emitEvent(event)
		}
	}
}

func (c *NetworkCollector) emitEvent(event core.Event) {
	if c.eventCh == nil {
		return
	}
	select {
	case c.eventCh <- event:
	default:
		log.Println("network collector: event channel full, dropping event")
	}
}

func (c *NetworkCollector) FlowCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.flows)
}

func (c *NetworkCollector) GetFlows() map[FlowKey]*FlowStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[FlowKey]*FlowStats, len(c.flows))
	for k, v := range c.flows {
		copy := *v
		result[k] = &copy
	}
	return result
}

func (c *NetworkCollector) InjectFlow(key FlowKey, stats *FlowStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flows[key] = stats
}

func isKnownMaliciousPort(port int) bool {
	maliciousPorts := map[int]bool{
		4444:  true, // Metasploit default
		5555:  true, // Android debug
		6666:  true, // IRC backdoor
		6667:  true, // IRC
		31337: true, // Back Orifice
		12345: true, // NetBus
		27374: true, // SubSeven
		1080:  true, // SOCKS proxy (common in malware)
	}
	return maliciousPorts[port]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
