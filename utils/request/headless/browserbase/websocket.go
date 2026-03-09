package browserbase

import (
	// Standard
	"context"
	"fmt"
	"net"

	// External
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type WebSocket struct {
	conn net.Conn
}

func NewWebSocket(ctx context.Context, url string) (*WebSocket, error) {
	conn, _, _, err := ws.Dial(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket: %w", err)
	}
	return &WebSocket{conn}, nil
}

func (w *WebSocket) Send(b []byte) error {
	return wsutil.WriteClientText(w.conn, b)
}

func (w *WebSocket) Read() ([]byte, error) {
	return wsutil.ReadServerText(w.conn)
}
