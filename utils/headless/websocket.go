package headless

import (
	"context"
	"log"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type WebSocket struct {
	conn net.Conn
}

type Options struct{}

func NewWebSocket(ctx context.Context, url string) *WebSocket {
	conn, _, _, err := ws.Dial(context.Background(), url)
	if err != nil {
		log.Fatal(err)
	}
	return &WebSocket{conn}
}

func (w *WebSocket) Send(b []byte) error {
	return wsutil.WriteClientText(w.conn, b)
}

func (w *WebSocket) Read() ([]byte, error) {
	return wsutil.ReadServerText(w.conn)
}
