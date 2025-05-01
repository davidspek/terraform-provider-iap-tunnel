package iap_tunnel

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/coder/websocket"
)

// Tunnel represents a bidirectional communication channel
type Tunnel interface {
	io.ReadWriteCloser
	Start(context.Context)
	Stop()
	Errors() <-chan error
}

// TunnelProtocol defines the protocol-specific operations
type TunnelProtocol interface {
	HandleMessage(context.Context, []byte) error
	CreateDataFrame([]byte) []byte
	CreateAckFrame(uint64) []byte
	ValidateMessage([]byte) error
	ExtractData([]byte) ([]byte, []byte, error)
	DataChannel() <-chan []byte
}

// TunnelManager handles tunnel lifecycle
type TunnelManager interface {
	// StartProxy(context.Context) error
	Serve(context.Context, net.Listener) error
	StartTunnel(context.Context, *websocket.Conn) (Tunnel, error)
	Errors() <-chan error
	Stop() error
}

// TokenProvider abstracts authentication operations
type TokenProvider interface {
	GetHeaders() (http.Header, error)
	RefreshToken(context.Context) error
}
