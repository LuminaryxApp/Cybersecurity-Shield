package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

type Agent struct {
	ID         string
	OrgID      string
	APIURL     string
	natsConn   *nats.Conn
	collectors []Collector
	eventCh    chan Event
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	heartbeat  time.Duration
}

func New(id, orgID, apiURL string, nc *nats.Conn, heartbeatSec int) *Agent {
	return &Agent{
		ID:        id,
		OrgID:     orgID,
		APIURL:    apiURL,
		natsConn:  nc,
		eventCh:   make(chan Event, 1000),
		heartbeat: time.Duration(heartbeatSec) * time.Second,
	}
}

func (a *Agent) Register(c Collector) {
	a.collectors = append(a.collectors, c)
}

func (a *Agent) Start(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)

	for _, c := range a.collectors {
		collector := c
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			log.Printf("starting collector: %s", collector.Name())
			if err := collector.Start(ctx, a.eventCh); err != nil {
				log.Printf("collector %s error: %v", collector.Name(), err)
			}
		}()
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.eventForwarder(ctx)
	}()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.heartbeatLoop(ctx)
	}()

	return nil
}

func (a *Agent) Stop() error {
	if a.cancel != nil {
		a.cancel()
	}
	for _, c := range a.collectors {
		if err := c.Stop(); err != nil {
			log.Printf("error stopping collector %s: %v", c.Name(), err)
		}
	}
	a.wg.Wait()
	return nil
}

func (a *Agent) CollectorCount() int {
	return len(a.collectors)
}

func (a *Agent) EventChannel() chan Event {
	return a.eventCh
}

func (a *Agent) eventForwarder(ctx context.Context) {
	subject := fmt.Sprintf("events.%s.%s", a.OrgID, a.ID)
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-a.eventCh:
			event.OrgID = a.OrgID
			event.AgentID = a.ID
			if event.Time.IsZero() {
				event.Time = time.Now()
			}

			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("failed to marshal event: %v", err)
				continue
			}

			if a.natsConn != nil {
				if err := a.natsConn.Publish(subject, data); err != nil {
					log.Printf("failed to publish event: %v", err)
				}
			}
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

func (a *Agent) sendHeartbeat() {
	url := fmt.Sprintf("%s/api/v1/agents/%s/heartbeat", a.APIURL, a.ID)
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		log.Printf("heartbeat request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("heartbeat failed: %v", err)
		return
	}
	resp.Body.Close()
}
