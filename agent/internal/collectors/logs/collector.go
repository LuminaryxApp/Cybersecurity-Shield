package logs

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/core"
)

type LogCollector struct {
	sources     []string
	syslogAddr  string
	eventCh     chan<- core.Event
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	syslogConn  net.PacketConn
}

func NewLogCollector(sources []string, syslogAddr string) *LogCollector {
	if syslogAddr == "" {
		syslogAddr = ":1514"
	}
	return &LogCollector{
		sources:    sources,
		syslogAddr: syslogAddr,
	}
}

func (c *LogCollector) Name() string {
	return "logs"
}

func (c *LogCollector) Start(ctx context.Context, eventCh chan<- core.Event) error {
	ctx, c.cancel = context.WithCancel(ctx)
	c.eventCh = eventCh

	for _, src := range c.sources {
		switch {
		case strings.HasPrefix(src, "syslog://"):
			addr := strings.TrimPrefix(src, "syslog://")
			if addr == "" {
				addr = c.syslogAddr
			}
			c.wg.Add(1)
			go func(a string) {
				defer c.wg.Done()
				c.runSyslogListener(ctx, a)
			}(addr)
		case strings.HasPrefix(src, "file://"):
			path := strings.TrimPrefix(src, "file://")
			c.wg.Add(1)
			go func(p string) {
				defer c.wg.Done()
				c.tailFile(ctx, p)
			}(path)
		default:
			if _, err := os.Stat(src); err == nil {
				c.wg.Add(1)
				go func(p string) {
					defer c.wg.Done()
					c.tailFile(ctx, p)
				}(src)
			} else {
				log.Printf("log collector: unknown source %q", src)
			}
		}
	}

	if len(c.sources) == 0 {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.runSyslogListener(ctx, c.syslogAddr)
		}()
	}

	c.wg.Wait()
	return nil
}

func (c *LogCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.syslogConn != nil {
		c.syslogConn.Close()
	}
	c.wg.Wait()
	return nil
}

func (c *LogCollector) runSyslogListener(ctx context.Context, addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("log collector: failed to start syslog listener on %s: %v", addr, err)
		return
	}
	c.syslogConn = conn

	log.Printf("log collector: syslog listener started on %s", addr)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("log collector: syslog read error: %v", err)
			continue
		}

		line := strings.TrimSpace(string(buf[:n]))
		if line == "" {
			continue
		}

		event := ParseSyslog(line)
		select {
		case c.eventCh <- event:
		default:
			log.Println("log collector: event channel full, dropping syslog event")
		}
	}
}

func (c *LogCollector) tailFile(ctx context.Context, path string) {
	parserFn := detectParser(path)

	file, err := os.Open(path)
	if err != nil {
		log.Printf("log collector: cannot open %s: %v", path, err)
		return
	}
	defer file.Close()

	file.Seek(0, 2)
	log.Printf("log collector: tailing %s", path)

	var partial []byte
	readBuf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, readErr := file.Read(readBuf)
		if n > 0 {
			partial = append(partial, readBuf[:n]...)

			for {
				idx := -1
				for i, b := range partial {
					if b == '\n' {
						idx = i
						break
					}
				}
				if idx == -1 {
					break
				}

				line := strings.TrimSpace(string(partial[:idx]))
				partial = partial[idx+1:]

				if line == "" {
					continue
				}

				event := parserFn(line)
				select {
				case c.eventCh <- event:
				default:
					log.Println("log collector: event channel full, dropping file event")
				}
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Printf("log collector: read error on %s: %v", path, readErr)
			return
		}
	}
}

func detectParser(path string) func(string) core.Event {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "nginx") && strings.Contains(lower, "access"):
		return ParseNginxAccess
	case strings.Contains(lower, "auth") || strings.Contains(lower, "secure"):
		return ParseAuthLog
	default:
		return ParseSyslog
	}
}

func (c *LogCollector) SyslogAddr() string {
	if c.syslogConn != nil {
		return c.syslogConn.LocalAddr().String()
	}
	return c.syslogAddr
}

func (c *LogCollector) EmitTestEvent(line string) {
	if c.eventCh == nil {
		return
	}
	event := ParseSyslog(line)
	select {
	case c.eventCh <- event:
	default:
	}
}

type FileSource struct {
	Path   string
	Parser string
}

func FormatSource(protocol, addr string) string {
	return fmt.Sprintf("%s://%s", protocol, addr)
}
