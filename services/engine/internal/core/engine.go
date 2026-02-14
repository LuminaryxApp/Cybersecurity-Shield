package core

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type Event struct {
	Time      time.Time              `json:"time"`
	OrgID     string                 `json:"org_id"`
	AgentID   string                 `json:"agent_id"`
	Source    string                 `json:"source"`
	Category  string                 `json:"category"`
	Severity  string                 `json:"severity"`
	RiskScore float32                `json:"risk_score"`
	Summary   string                 `json:"summary"`
	Payload   map[string]interface{} `json:"payload"`
}

type EventHandler func(event Event) error

type Pipeline struct {
	Name    string
	Handler EventHandler
}

type Engine struct {
	nc        *nats.Conn
	db        *pgxpool.Pool
	subs      []*nats.Subscription
	pipelines []Pipeline
	eventCh   chan Event
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	processed int64
}

func New(nc *nats.Conn, db *pgxpool.Pool) *Engine {
	return &Engine{
		nc:      nc,
		db:      db,
		eventCh: make(chan Event, 5000),
	}
}

func (e *Engine) RegisterPipeline(name string, handler EventHandler) {
	e.pipelines = append(e.pipelines, Pipeline{
		Name:    name,
		Handler: handler,
	})
}

func (e *Engine) Start(ctx context.Context) error {
	ctx, e.cancel = context.WithCancel(ctx)

	sub, err := e.nc.Subscribe("events.>", func(msg *nats.Msg) {
		var event Event
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			log.Printf("engine: failed to unmarshal event: %v", err)
			return
		}

		select {
		case e.eventCh <- event:
		default:
			log.Println("engine: event channel full, dropping event")
		}
	})
	if err != nil {
		return err
	}
	e.subs = append(e.subs, sub)

	for i := 0; i < 4; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.processEvents(ctx)
		}()
	}

	log.Printf("engine: started with %d pipelines", len(e.pipelines))
	return nil
}

func (e *Engine) Stop() error {
	for _, sub := range e.subs {
		sub.Unsubscribe()
	}
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	return nil
}

func (e *Engine) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-e.eventCh:
			e.runPipelines(event)
			e.mu.Lock()
			e.processed++
			e.mu.Unlock()
		}
	}
}

func (e *Engine) runPipelines(event Event) {
	for _, p := range e.pipelines {
		if err := p.Handler(event); err != nil {
			log.Printf("engine: pipeline %s error: %v", p.Name, err)
		}
	}
}

func (e *Engine) ProcessedCount() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.processed
}

func (e *Engine) PipelineCount() int {
	return len(e.pipelines)
}

func (e *Engine) InjectEvent(event Event) {
	select {
	case e.eventCh <- event:
	default:
	}
}

func (e *Engine) DB() *pgxpool.Pool {
	return e.db
}
