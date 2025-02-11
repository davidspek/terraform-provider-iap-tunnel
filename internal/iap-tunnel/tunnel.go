// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iap_tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"golang.org/x/oauth2"
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
	conn    *websocket.Conn
	inbound chan []byte
	acks    chan uint64

	outboundLock    sync.Mutex
	totalInboundLen uint64

	// cancel will shut down the readLoop gracefully.
	cancel   context.CancelFunc
	writeCtx context.Context
}

// newTunnelAdapter creates a tunnelAdapter and sets up inbound channels.
func newTunnelAdapter(conn *websocket.Conn) *tunnelAdapter {
	return &tunnelAdapter{
		conn:    conn,
		inbound: make(chan []byte),
		acks:    make(chan uint64),
	}
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
	_ = a.conn.Close(websocket.StatusNormalClosure, "")
}

// readLoop continuously reads messages until error or context cancellation.
func (a *tunnelAdapter) readLoop(ctx context.Context) {
	eg, rCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		defer close(a.inbound)
		return a.inboundHandler(rCtx)
	})
	if err := eg.Wait(); err != nil && err != context.Canceled {
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
	if len(msg) < SUBPROTOCOL_TAG_LEN {
		return errors.New("inbound message too short for subprotocol tag")
	}
	subprotocolTag, msg, err := ExtractSubprotocolTag(msg)
	if err != nil {
		return fmt.Errorf("unable to extract subprotocol tag: %w", err)
	}

	switch subprotocolTag {
	case SUBPROTOCOL_TAG_CONNECT_SUCCESS_SID:
		sidVal, remainder, err := ExtractSubprotocolConnectSuccessSid(msg)
		if err != nil {
			return fmt.Errorf("failed to parse connect success SID: %w", err)
		}
		if len(remainder) > 0 {
			fmt.Println("extra data after connect success SID")
		}
		// Here you can log it, store it, or do any needed post-connection logic.
		fmt.Printf("Received CONNECT_SUCCESS_SID: %d\n", sidVal)
	case SUBPROTOCOL_TAG_ACK:
		ackVal, remainder, err := ExtractSubprotocolAck(msg)
		if err != nil {
			return fmt.Errorf("failed to parse ACK: %w", err)
		}
		if len(remainder) > 0 {
			fmt.Println("extra data after ACK")
		}

		// Send the parsed ackVal along the acks channel if you want to react to it.
		select {
		case a.acks <- ackVal:
			// Optionally log or track “ackVal” anywhere else you need.
			fmt.Printf("Received ACK for %d bytes\n", ackVal)
		default:
			// If nothing is listening, you can drop it or buffer it differently.
		}
	case SUBPROTOCOL_TAG_DATA:
		data, remainder, err := ExtractSubprotocolData(msg)
		if err != nil {
			return fmt.Errorf("unable to extract subprotocol data: %w", err)
		}
		if len(remainder) > 0 {
			fmt.Println("extra data after subprotocol data")
		}
		a.inbound <- data
		a.totalInboundLen += uint64(len(data))
		if err := a.inboundAck(ctx, a.totalInboundLen); err != nil {
			fmt.Println("inbound ack error:", err)
		}
	default:
		return errors.New("unknown subprotocol tag")
	}
	return nil
}

// inboundAck sends a subprotocol ACK with the total inbound length.
func (a *tunnelAdapter) inboundAck(ctx context.Context, length uint64) error {
	a.outboundLock.Lock()
	defer a.outboundLock.Unlock()

	if err := a.conn.Write(ctx, websocket.MessageBinary, CreateSubprotocolAckFrame(length)); err != nil {
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
	for i := 0; i < len(p); i += SUBPROTOCOL_MAX_DATA_FRAME_SIZE {
		maxOrEnd := i + SUBPROTOCOL_MAX_DATA_FRAME_SIZE
		if maxOrEnd > len(p) {
			maxOrEnd = len(p)
		}
		chunk := p[i:maxOrEnd]

		frame := CreateSubprotocolDataFrame(chunk)

		a.outboundLock.Lock()
		err := a.conn.Write(a.writeCtx, websocket.MessageBinary, frame)
		a.outboundLock.Unlock()
		if err != nil {
			return 0, fmt.Errorf("unable to write to websocket: %w", err)
		}
	}
	return len(p), nil
}

// Close is part of io.Closer. Stop the read loop, then close the channel.
func (a *tunnelAdapter) Close() error {
	a.Stop()
	return nil
}

// TunnelManager manages creation of our WebSocket-based tunnel.
type TunnelManager struct {
	LocalPort int
	Target    IapTunnelTarget
	ts        oauth2.TokenSource
}

// getHeaders fetches OAuth2 tokens and returns the necessary headers.
func (m *TunnelManager) getHeaders() (http.Header, error) {
	tok, err := m.ts.Token()
	if err != nil {
		return nil, fmt.Errorf("unable to get token: %w", err)
	}
	return http.Header{
		"Origin":        []string{TUNNEL_CLOUDPROXY_ORIGIN},
		"User-Agent":    []string{TUNNEL_USER_AGENT},
		"Authorization": []string{fmt.Sprintf("Bearer %s", tok.AccessToken)},
	}, nil
}

func (m *TunnelManager) SetTokenSource(source oauth2.TokenSource) {
	m.ts = source
}

// StartSocket dial a WebSocket connection to the target and return the connection.
func (m *TunnelManager) StartSocket(ctx context.Context) (*websocket.Conn, error) {
	var err error
	if m.ts == nil {
		// m.ts, err = auth.TokenSource()
		// if err != nil {
		// 	return nil, fmt.Errorf("unable to get TokenSource: %w", err)
		// }
		src, err := google.DefaultTokenSource(ctx, oauthsvc.UserinfoEmailScope)
		if err != nil {
			return nil, fmt.Errorf("unable to acquire token source: %w", err)
		}
		m.SetTokenSource(src)
	}

	u, err := CreateWebSocketConnectURL(m.Target, false)

	headers, err := m.getHeaders()
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
func (m *TunnelManager) StartTunnel(ctx context.Context, conn *websocket.Conn) (io.ReadWriteCloser, error) {

	adapter := newTunnelAdapter(conn)
	adapter.Start(ctx)
	return adapter, nil
}

// StartProxy listens on LocalPort, creates a new tunnel, then copies data in both directions.
func (m *TunnelManager) StartProxy(ctx context.Context) error {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", m.LocalPort))
	if err != nil {
		return fmt.Errorf("unable to listen on port %d: %w", m.LocalPort, err)
	}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				// return fmt.Errorf("unable to accept connection: %w", err)
			}
			websocketConn, err := m.StartSocket(ctx)
			tunnel, err := m.StartTunnel(ctx, websocketConn)
			if err != nil {
				_ = conn.Close()
				// return fmt.Errorf("unable to start tunnel: %w", err)
			}

			go func() {
				// defer tunnel.Close()
				// defer conn.Close()
				_, copyErr := io.Copy(conn, tunnel)
				if copyErr != nil && !errors.Is(copyErr, io.EOF) {
					fmt.Println("copy from tunnel failed:", copyErr)
				}
			}()

			go func() {
				// defer tunnel.Close()
				// defer conn.Close()
				_, copyErr := io.Copy(tunnel, conn)
				if copyErr != nil && !errors.Is(copyErr, io.EOF) {
					fmt.Println("copy to tunnel failed:", copyErr)
				}
			}()
		}
	}()
	return nil
}

// StopProxy closes the listener on LocalPort and the tunnel.
// func (m *TunnelManager) StopProxy() error {
