package messaging

import "github.com/nats-io/nats.go"

type Bus struct {
	conn *nats.Conn
}

func New(conn *nats.Conn) *Bus {
	return &Bus{conn: conn}
}

func Connect(url, token string) (*Bus, error) {
	opts := []nats.Option{}
	if token != "" {
		opts = append(opts, nats.Token(token))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, err
	}
	return &Bus{conn: nc}, nil
}

func (b *Bus) Publish(subject string, data []byte) error {
	return b.conn.Publish(subject, data)
}

func (b *Bus) Subscribe(subject string, handler func([]byte)) error {
	_, err := b.conn.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
	})
	return err
}

func (b *Bus) Conn() *nats.Conn {
	return b.conn
}

func (b *Bus) Close() {
	b.conn.Close()
}
