// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iap_tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
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

// tunnelAdapter abstracts the IAP WebSocket tunnel to an io.ReadWriteCloser.
type tunnelAdapter struct {
	conn     *websocket.Conn
	protocol TunnelProtocol
	inbound  chan []byte
	errors   chan error
	cancel   context.CancelFunc
	writeCtx context.Context
}

// NewTunnelAdapter creates a tunnelAdapter and sets up inbound channels.
func NewTunnelAdapter(conn *websocket.Conn, protocol TunnelProtocol) Tunnel {
	return &tunnelAdapter{
		conn:     conn,
		protocol: protocol,
		inbound:  make(chan []byte),
		errors:   make(chan error, 100),
	}
}

func (a *tunnelAdapter) Errors() <-chan error {
	return a.errors
}

// Start begins reading inbound messages in a separate goroutine.
func (a *tunnelAdapter) Start(ctx context.Context) {
	ctx, a.cancel = context.WithCancel(ctx)
	a.writeCtx = ctx
	go a.readLoop(ctx)
}

// Stop signals the reading goroutine to stop and closes the connection.
func (a *tunnelAdapter) Stop() {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	// Do not close a.inbound or a.errors here; let readLoop handle it.
}

// readLoop continuously reads messages until error or context cancellation.
func (a *tunnelAdapter) readLoop(ctx context.Context) {
	eg, rCtx := errgroup.WithContext(ctx)

	// Handle incoming messages
	eg.Go(func() error {
		defer close(a.inbound)
		return a.inboundHandler(rCtx)
	})

	// Forward data from protocol to adapter
	eg.Go(func() error {
		for {
			select {
			case <-rCtx.Done():
				return rCtx.Err()
			case data, ok := <-a.protocol.DataChannel():
				if !ok {
					return nil
				}
				select {
				case a.inbound <- data:
				case <-rCtx.Done():
					return rCtx.Err()
				}
			}
		}
	})
	if err := eg.Wait(); err != nil && err != context.Canceled && err != io.EOF {
		fmt.Println("readLoop error:", err)
	}
}

// inboundHandler parses each incoming message and sends it to the inbound channel.
func (a *tunnelAdapter) inboundHandler(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, msg, err := a.conn.Read(ctx)
		if errors.Is(err, context.Canceled) || websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return nil
		} else if err != nil {
			// Gracefully handle Postgres connection closed (status 4010)
			if websocket.CloseStatus(err) == 4010 {
				return io.EOF
			}
			return fmt.Errorf("error while reading message: %w", err)
		}
		err = a.parseSubprotocolMessage(ctx, msg)
		if err != nil {
			return err
		}
	}
}

// parseSubprotocolMessage handles framing or subprotocol tags, and dispatches data as needed.
func (a *tunnelAdapter) parseSubprotocolMessage(ctx context.Context, msg []byte) error {
	return a.protocol.HandleMessage(ctx, msg)
}

// inboundAck sends a subprotocol ACK with the total inbound length.
func (a *tunnelAdapter) inboundAck(ctx context.Context, length uint64) error {
	frame := a.protocol.CreateAckFrame(length)
	if err := a.conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
		return fmt.Errorf("unable to write inbound ack: %w", err)
	}
	return nil
}

// Read implements io.Reader by pulling from the inbound channel.
func (a *tunnelAdapter) Read(p []byte) (int, error) {
	msg, ok := <-a.inbound
	if !ok {
		return 0, io.EOF
	}
	copied := copy(p, msg)
	return copied, nil
}

// Write implements io.Writer by splitting data into frames and sending them.
func (a *tunnelAdapter) Write(p []byte) (int, error) {
	frame := a.protocol.CreateDataFrame(p)
	if err := a.conn.Write(a.writeCtx, websocket.MessageBinary, frame); err != nil {
		return 0, fmt.Errorf("write failed: %w", err)
	}
	return len(p), nil
}

// Close is part of io.Closer. Stop the read loop, then close the channel.
func (a *tunnelAdapter) Close() error {
	a.Stop()
	return nil
}

type tunnelManager struct {
	Target        IapTunnelTarget
	auth          TokenProvider
	errors        chan error
	currentTunnel Tunnel
	mu            sync.Mutex // protect currentTunnel access
}

func NewTunnelManager(target IapTunnelTarget) TunnelManager {
	return &tunnelManager{
		Target: target,
		// auth:      auth,
		errors: make(chan error, 100),
	}
}

func (m *tunnelManager) Errors() <-chan error {
	return m.errors
}

func (m *tunnelManager) SetTokenProvider(prov TokenProvider) {
	m.auth = prov
}

// StartSocket dial a WebSocket connection to the target and return the connection.
func (m *tunnelManager) StartSocket(ctx context.Context) (*websocket.Conn, error) {
	var err error
	if m.auth == nil {
		src, err := google.DefaultTokenSource(ctx, oauthsvc.UserinfoEmailScope)
		if err != nil {
			return nil, fmt.Errorf("unable to acquire token source: %w", err)
		}
		m.SetTokenProvider(NewOAuthTokenProvider(src))
	}

	u, err := CreateWebSocketConnectURL(m.Target, true)

	headers, err := m.auth.GetHeaders()
	if err != nil {
		return nil, fmt.Errorf("unable to construct headers: %w", err)
	}

	opts := &websocket.DialOptions{
		HTTPHeader:   headers,
		Subprotocols: []string{SUBPROTOCOL_NAME},
	}

	conn, _, err := websocket.Dial(ctx, u, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to dial WebSocket: %w", err)
	}
	return conn, nil
}

// StartTunnel starts a single WebSocket tunnel and returns an io.ReadWriteCloser for data flow.
func (m *tunnelManager) StartTunnel(ctx context.Context, conn *websocket.Conn) (Tunnel, error) {
	adapter := NewTunnelAdapter(conn, NewIAPTunnelProtocol())
	adapter.Start(ctx)

	m.mu.Lock()
	if m.currentTunnel != nil {
		m.currentTunnel.Stop()
	}
	m.currentTunnel = adapter
	m.mu.Unlock()

	return adapter, nil
}

// Serve accepts a user-provided net.Listener and handles incoming connections.
func (m *tunnelManager) Serve(ctx context.Context, lis net.Listener) error {
	fmt.Printf("[IAP Tunnel] Serving on %s\n", lis.Addr())
	defer func() {
		fmt.Println("[IAP Tunnel] Listener closed, shutting down Serve loop.")
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
				fmt.Println("[IAP Tunnel] Listener closed or context cancelled, exiting Serve loop.")
				return nil
			}
			select {
			case m.errors <- fmt.Errorf("accept error: %w", err):
			default:
			}
			continue
		}

		go func(conn net.Conn) {
			defer func() {
				conn.Close()
				fmt.Println("[IAP Tunnel] Closed accepted connection.")
			}()

			websocketConn, err := m.StartSocket(ctx)
			if err != nil {
				fmt.Printf("[IAP Tunnel] Failed to start websocket: %v\n", err)
				return
			}
			defer func() {
				websocketConn.Close(websocket.StatusNormalClosure, "connection handler done")
				fmt.Println("[IAP Tunnel] Websocket connection closed.")
			}()

			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			tunnel, err := m.StartTunnel(ctx, websocketConn)
			if err != nil {
				fmt.Printf("[IAP Tunnel] Failed to start tunnel: %v\n", err)
				return
			}
			defer func() {
				tunnel.Close()
				fmt.Println("[IAP Tunnel] Tunnel closed gracefully.")
			}()

			if err := handleConnection(ctx, conn, tunnel); err != nil {
				select {
				case m.errors <- fmt.Errorf("connection error: %w", err):
				default:
				}
			}
		}(conn)
	}
}

// // StartProxy listens on LocalPort, creates a new tunnel, then copies data in both directions.
// func (m *tunnelManager) StartProxy(ctx context.Context) error {
// 	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", m.LocalPort))
// 	if err != nil {
// 		return fmt.Errorf("unable to listen on port %d: %w", m.LocalPort, err)
// 	}
// 	fmt.Printf("Listening on localhost:%d\n", m.LocalPort)
// 	defer lis.Close()

// 	for {
// 		conn, err := lis.Accept()
// 		if err != nil {
// 			if errors.Is(err, net.ErrClosed) {
// 				return nil
// 			}
// 			continue
// 		}

// 		go func(conn net.Conn) {
// 			defer conn.Close()

// 			websocketConn, err := m.StartSocket(ctx)
// 			if err != nil {
// 				fmt.Printf("Failed to start websocket: %v\n", err)
// 				return
// 			}
// 			defer websocketConn.Close(websocket.StatusNormalClosure, "")

// 			tcpConn := conn.(*net.TCPConn)
// 			tcpConn.SetKeepAlive(true)
// 			tcpConn.SetKeepAlivePeriod(30 * time.Second)

// 			tunnel, err := m.StartTunnel(ctx, websocketConn)
// 			if err != nil {
// 				fmt.Printf("Failed to start tunnel: %v\n", err)
// 				return
// 			}
// 			defer tunnel.Close()

// 			if err := handleConnection(ctx, conn, tunnel); err != nil {
// 				select {
// 				case m.errors <- fmt.Errorf("connection error: %w", err):
// 				default:
// 				}
// 			}
// 		}(conn)
// 	}
// }

// handleConnection uses an errgroup to copy data in both directions,
// returning an error if any copy fails.
func handleConnection(ctx context.Context, conn net.Conn, tunnel io.ReadWriteCloser) error {
	g, gCtx := errgroup.WithContext(ctx)

	// Create a done channel to signal completion
	done := make(chan struct{})
	defer close(done)

	g.Go(func() error {
		defer func() {
			conn.(*net.TCPConn).CloseRead()
			select {
			case done <- struct{}{}:
			default:
			}
		}()
		_, err := io.Copy(conn, tunnel)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("copy from tunnel failed: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		defer func() {
			conn.(*net.TCPConn).CloseWrite()
			select {
			case done <- struct{}{}:
			default:
			}
		}()
		_, err := io.Copy(tunnel, conn)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("copy to tunnel failed: %w", err)
		}
		return nil
	})

	// Wait for either context cancellation or copy completion
	select {
	case <-gCtx.Done():
		return gCtx.Err()
	case <-done:
		// One of the copies completed, wait for cleanup
		err := g.Wait()
		if errors.Is(err, io.EOF) || isConnectionReset(err) {
			return nil
		}
		return err
	}
}

func (m *tunnelManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentTunnel != nil {
		fmt.Println("[IAP Tunnel] Stopping current tunnel...")
		m.currentTunnel.Stop()
		// Attempt to close the underlying websocket connection if possible
		if adapter, ok := m.currentTunnel.(*tunnelAdapter); ok && adapter.conn != nil {
			fmt.Println("[IAP Tunnel] Closing underlying websocket connection...")
			adapter.conn.Close(websocket.StatusNormalClosure, "tunnel manager stopped")
		}
		m.currentTunnel = nil
		fmt.Println("[IAP Tunnel] Tunnel stopped gracefully.")
	} else {
		fmt.Println("[IAP Tunnel] No active tunnel to stop.")
	}
	return nil
}

func isConnectionReset(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "broken pipe")
}
