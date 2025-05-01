package iap_tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	oauthsvc "google.golang.org/api/oauth2/v2"
)

// Common URL and SubProtocol constants.
const (
	URL_SCHEME               = "wss"
	URL_HOST                 = "tunnel.cloudproxy.app"
	MTLS_URL_HOST            = "mtls.tunnel.cloudproxy.app"
	URL_PATH_ROOT            = "/v4"
	CONNECT_ENDPOINT         = "connect"
	RECONNECT_ENDPOINT       = "reconnect"
	SEC_PROTOCOL_SUFFIX      = "bearer.relay.tunnel.cloudproxy.app"
	TUNNEL_CLOUDPROXY_ORIGIN = "bot:iap-tunneler"
	TUNNEL_USER_AGENT        = "go-iap-tunnel"

	SUBPROTOCOL_NAME                = "relay.tunnel.cloudproxy.app"
	SUBPROTOCOL_TAG_LEN             = 2
	SUBPROTOCOL_HEADER_LEN          = SUBPROTOCOL_TAG_LEN + 4
	SUBPROTOCOL_MAX_DATA_FRAME_SIZE = 16384

	SUBPROTOCOL_TAG_CONNECT_SUCCESS_SID   uint16 = 0x0001
	SUBPROTOCOL_TAG_RECONNECT_SUCCESS_ACK uint16 = 0x0002
	SUBPROTOCOL_TAG_DATA                  uint16 = 0x0004
	SUBPROTOCOL_TAG_ACK                   uint16 = 0x0007
)

// TunnelTarget describes the remote IAP tunnel endpoint.
type TunnelTarget struct {
	Project     string
	Zone        string
	Instance    string
	Interface   string
	Port        int
	URLOverride string
	Network     string
	Region      string
	Host        string
	DestGroup   string
}

// NewTunnelAdapter creates a TunnelAdapter that implements io.ReadWriteCloser over the IAP websocket connection.
// protocol should implement your IAP tunnel protocol logic.
func NewTunnelAdapter(wsConn *websocket.Conn, protocol *IAPTunnelProtocol) *tunnelAdapter {
	return &tunnelAdapter{
		conn:     wsConn,
		protocol: protocol,
		inbound:  make(chan []byte, 100),
		errors:   make(chan error, 10),
		closed:   make(chan struct{}),
	}
}

// tunnelAdapter implements io.ReadWriteCloser for the tunnel.
type tunnelAdapter struct {
	conn     *websocket.Conn
	protocol *IAPTunnelProtocol
	inbound  chan []byte
	errors   chan error
	closed   chan struct{}
	pending  []byte
}

func (t *tunnelAdapter) Read(p []byte) (int, error) {
	// Serve any pending data first
	if len(t.pending) > 0 {
		n := copy(p, t.pending)
		t.pending = t.pending[n:]
		return n, nil
	}

	select {
	case data, ok := <-t.inbound:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		// Save any leftover bytes for the next Read
		if n < len(data) {
			t.pending = data[n:]
		}
		return n, nil
	case <-t.closed:
		return 0, io.EOF
	}
}

func (t *tunnelAdapter) Write(p []byte) (int, error) {
	// Implement protocol-specific write logic here.
	// For example, wrap p in a protocol frame and send via t.conn.
	err := t.protocol.SendDataFrame(t.conn, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *tunnelAdapter) Close() error {
	close(t.closed)
	return t.conn.Close(websocket.StatusNormalClosure, "tunnel closed")
}

// Start launches goroutines to handle inbound websocket messages and protocol parsing.
func (t *tunnelAdapter) Start(ctx context.Context) {
	go func() {
		defer close(t.inbound)
		for {
			_, msg, err := t.conn.Read(ctx)
			if err != nil {
				t.errors <- err
				return
			}
			// Parse protocol and push data frames to t.inbound
			data, err := t.protocol.ParseDataFrame(msg)
			if err != nil {
				t.errors <- err
				return
			}
			t.inbound <- data
		}
	}()
}

// TunnelManager manages the lifecycle of a local TCP listener and IAP tunnel connections.
type TunnelManager struct {
	target TunnelTarget
	auth   TokenProvider

	mu      sync.Mutex
	errors  chan error
	running bool
}

// NewTunnelManager creates a new TunnelManager.
func NewTunnelManager(target TunnelTarget, auth TokenProvider) *TunnelManager {
	return &TunnelManager{
		target: target,
		auth:   auth,
		errors: make(chan error, 100),
	}
}

// Errors returns a channel for asynchronous error reporting.
func (m *TunnelManager) Errors() <-chan error {
	return m.errors
}

// Serve starts accepting connections on the provided listener and proxies them via IAP.
func (m *TunnelManager) Serve(ctx context.Context, lis net.Listener) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("tunnel manager already running")
	}
	m.running = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	fmt.Printf("[IAP Tunnel] Serving on %s\n", lis.Addr())
	defer fmt.Println("[IAP Tunnel] Listener closed, shutting down Serve loop.")

	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			select {
			case m.errors <- fmt.Errorf("accept error: %w", err):
			default:
			}
			continue
		}
		go m.handleConn(ctx, conn)
	}
}

// handleConn proxies a single TCP connection via IAP WebSocket.
func (m *TunnelManager) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	fmt.Printf("[IAP Tunnel] Accepted connection from %s\n", conn.RemoteAddr())

	wsConn, _, err := m.startWebSocket(ctx)
	if err != nil {
		fmt.Printf("[IAP Tunnel] Failed to start websocket: %v\n", err)
		return
	}
	defer wsConn.Close(websocket.StatusNormalClosure, "handler done")

	tunnel := NewTunnelAdapter(wsConn, NewIAPTunnelProtocol())
	tunnel.Start(ctx)
	defer tunnel.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	if err := proxyBidirectional(ctx, conn, tunnel); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		fmt.Printf("[IAP Tunnel] Proxy error: %v\n", err)
	}
	fmt.Printf("[IAP Tunnel] Closed connection from %s\n", conn.RemoteAddr())
}

// startWebSocket establishes a websocket connection to the IAP tunnel backend.
func (m *TunnelManager) startWebSocket(ctx context.Context) (*websocket.Conn, *http.Response, error) {
	if m.auth == nil {
		src, err := google.DefaultTokenSource(ctx, oauthsvc.UserinfoEmailScope)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to acquire token source: %w", err)
		}
		m.auth = NewOAuthTokenProvider(src)
	}
	u, err := CreateWebSocketConnectURL(m.target, true)
	if err != nil {
		return nil, nil, err
	}
	headers, err := m.auth.GetHeaders()
	if err != nil {
		return nil, nil, err
	}
	opts := &websocket.DialOptions{
		HTTPHeader:   headers,
		Subprotocols: []string{SUBPROTOCOL_NAME},
	}
	return websocket.Dial(ctx, u, opts)
}

// proxyBidirectional copies data in both directions until either side closes.
func proxyBidirectional(ctx context.Context, a, b io.ReadWriteCloser) error {
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		_, err := io.Copy(a, b)
		if err != nil {
			fmt.Printf("[IAP Tunnel] Error copying from a to b: %v\n", err)
		}
		return err
	})
	g.Go(func() error {
		_, err := io.Copy(b, a)
		if err != nil {
			fmt.Printf("[IAP Tunnel] Error copying from b to a: %v\n", err)
		}
		return err
	})
	return g.Wait()
}
