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

// TunnelAdapter implements io.ReadWriteCloser for the tunnel.
type TunnelAdapter struct {
	conn            *websocket.Conn
	protocol        TunnelProtocol
	target          TunnelTarget
	inbound         chan []byte
	totalInboundLen uint64
	pending         []byte
	errors          chan error
	closed          chan struct{}
	ready           chan struct{}
}

// NewTunnelAdapter creates a TunnelAdapter that implements io.ReadWriteCloser over the IAP websocket connection.
// protocol should implement your IAP tunnel protocol logic.
func NewTunnelAdapter(wsConn *websocket.Conn, target TunnelTarget) *TunnelAdapter {
	return &TunnelAdapter{
		conn:     wsConn,
		protocol: NewIAPTunnelProtocol(),
		target:   target,
		inbound:  make(chan []byte, 100),
		errors:   make(chan error, 100),
		closed:   make(chan struct{}),
		ready:    make(chan struct{}),
	}
}

func (t *TunnelAdapter) Read(p []byte) (int, error) {
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

func (t *TunnelAdapter) Write(p []byte) (int, error) {
	err := t.protocol.SendDataFrame(t.conn, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *TunnelAdapter) Close() error {
	close(t.closed)
	return t.conn.Close(websocket.StatusNormalClosure, "tunnel closed")
}

// Start launches goroutines to handle inbound websocket messages and protocol parsing.
func (t *TunnelAdapter) Start(ctx context.Context) {
	go func() {
		defer close(t.inbound)
		defer close(t.errors)
		var sid uint64
		var ackBytes uint64
		var wsConn = t.conn

		fmt.Println("ACK bytes:", ackBytes)
		// var err error
		for {
			_, msg, err := wsConn.Read(ctx)
			if err != nil {
				// Attempt reconnect if not context cancellation
				if ctx.Err() == nil && sid != 0 {
					reconnectURL, _ := CreateWebSocketReconnectURL(
						t.target, sid, ackBytes, true,
					)
					wsConn, _, err = websocket.Dial(ctx, reconnectURL, nil)
					if err != nil {
						t.errors <- fmt.Errorf("reconnect failed: %w", err)
						return
					}
					continue
				}
				t.errors <- err
				return
			}
			// Parse protocol and push data frames to t.inbound
			frameType, parsedMsg, err := t.protocol.ParseFrame(msg)
			if err != nil {
				t.errors <- err
				return
			}
			switch frameType {
			case SUBPROTOCOL_TAG_CONNECT_SUCCESS_SID:
				fmt.Println("Received Connect Success SID frame")
				sid, _, err = t.protocol.ExtractSubprotocolConnectSuccessSid(parsedMsg)
				if err != nil {
					t.errors <- fmt.Errorf("unable to extract connect success SID: %w", err)
				}

				select {
				case <-t.ready:
					// already closed
				default:
					close(t.ready)
				}
			case SUBPROTOCOL_TAG_RECONNECT_SUCCESS_ACK:
				fmt.Println("Received RECONNECT_SUCCESS_ACK frame")
				ackBytes, _, err = t.protocol.ExtractSubprotocolAck(parsedMsg)
				if err != nil {
					t.errors <- fmt.Errorf("unable to extract ack from reconnect success: %w", err)
				}
			case SUBPROTOCOL_TAG_ACK:
				fmt.Println("Received ACK frame")
				ackBytes, _, err = t.protocol.ExtractSubprotocolAck(parsedMsg)
				if err != nil {
					t.errors <- fmt.Errorf("unable to extract ack: %w", err)
				}
			case SUBPROTOCOL_TAG_DATA:
				fmt.Println("Received data frame")
				data, _, err := t.protocol.ExtractData(parsedMsg)
				if err != nil {
					t.errors <- fmt.Errorf("unable to extract data: %w", err)
				}
				if data != nil {
					t.inbound <- data
					t.totalInboundLen += uint64(len(data))
					// Send ACK after receiving enough data
					if t.totalInboundLen > 2*SUBPROTOCOL_MAX_DATA_FRAME_SIZE {
						// Send ACK frame
						err := t.protocol.SendAckFrame(t.conn, t.totalInboundLen)
						if err != nil {
							t.errors <- err
						}
						// Reset counter or adjust as needed
						t.totalInboundLen = 0
					}
				}
			default:
				fmt.Printf("Unknown frame type: %d\n", frameType)
			}
		}
	}()
}

// Ready returns a channel that signals when the tunnel is ready.
func (t *TunnelAdapter) Ready() <-chan struct{} {
	return t.ready
}

// TunnelManager manages the lifecycle of a local TCP listener and IAP tunnel connections.
type TunnelManager struct {
	target TunnelTarget
	auth   TokenProvider

	lastTunnel *TunnelAdapter
	mu         sync.Mutex
	errors     chan error
	running    bool
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

	tunnel := NewTunnelAdapter(wsConn, m.target)
	m.mu.Lock()
	m.lastTunnel = tunnel
	m.mu.Unlock()
	tunnel.Start(ctx)
	defer tunnel.Close()
	go func() {
		for err := range tunnel.errors {
			select {
			case m.errors <- err:
			default:
			}
		}
	}()

	// Wait for CONNECT_SUCCESS before proxying
	select {
	case <-tunnel.ready:
		// Tunnel is ready
	case <-ctx.Done():
		return
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	if err := proxyBidirectional(ctx, conn, tunnel); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		fmt.Printf("[IAP Tunnel] Proxy error: %v\n", err)
	}
	fmt.Printf("[IAP Tunnel] Closed connection from %s\n", conn.RemoteAddr())
}

func (m *TunnelManager) Ready() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastTunnel != nil {
		return m.lastTunnel.Ready()
	}
	// Return a closed channel if not available
	ch := make(chan struct{})
	close(ch)
	return ch
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
	g.Go(func() error { _, err := io.Copy(a, b); return err })
	g.Go(func() error { _, err := io.Copy(b, a); return err })
	return g.Wait()
}
