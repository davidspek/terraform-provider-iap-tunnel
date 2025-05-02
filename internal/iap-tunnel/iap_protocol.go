package iap_tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/coder/websocket"
)

type IAPTunnelProtocol struct {
	mu              sync.RWMutex
	totalInboundLen uint64
	errors          chan error
	connected       bool
	sid             uint64
	ready           chan struct{}
}

func NewIAPTunnelProtocol(ready chan struct{}) *IAPTunnelProtocol {
	return &IAPTunnelProtocol{
		errors: make(chan error, 100),
		ready:  ready,
	}
}

// SendDataFrame sends a data frame over the websocket connection using the IAP tunnel protocol.
func (p *IAPTunnelProtocol) SendDataFrame(conn *websocket.Conn, data []byte) error {
	frame := p.CreateDataFrame(data)
	ctx := context.Background()
	// Use websocket.MessageBinary for binary frames
	writer, err := conn.Writer(ctx, websocket.MessageBinary)
	if err != nil {
		return fmt.Errorf("failed to get websocket writer: %w", err)
	}
	_, err = writer.Write(frame)
	fmt.Println("Sent data frame:", frame)
	if err != nil {
		writer.Close()
		return fmt.Errorf("failed to write data frame: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close websocket writer: %w", err)
	}
	return nil
}

func (p *IAPTunnelProtocol) ParseDataFrame(msg []byte) ([]byte, error) {
	if err := p.ValidateMessage(msg); err != nil {
		return nil, err
	}

	subprotocolTag, msg, err := p.ExtractSubprotocolTag(msg)
	if err != nil {
		return nil, fmt.Errorf("unable to extract subprotocol tag: %w", err)
	}

	switch subprotocolTag {
	case SUBPROTOCOL_TAG_CONNECT_SUCCESS_SID:
		fmt.Println("Received Connect Success SID frame")
		return p.handleConnectSuccess(msg)
	case SUBPROTOCOL_TAG_ACK:
		fmt.Println("Received ACK frame")
		return p.handleAck(msg)
	case SUBPROTOCOL_TAG_DATA:
		fmt.Println("Received data frame")
		return p.handleData(msg)
	default:
		return nil, errors.New("unknown subprotocol tag")
	}
}

func (p *IAPTunnelProtocol) ValidateMessage(msg []byte) error {
	if len(msg) < SUBPROTOCOL_TAG_LEN {
		return errors.New("inbound message too short for subprotocol tag")
	}
	return nil
}

func (p *IAPTunnelProtocol) handleConnectSuccess(msg []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	sid, _, err := p.ExtractSubprotocolConnectSuccessSid(msg)
	if err != nil {
		return nil, fmt.Errorf("unable to extract connect success SID: %w", err)
	}
	p.connected = true
	p.sid = sid
	// Signal readiness
	select {
	case <-p.ready:
		// already closed
	default:
		close(p.ready)
	}
	return nil, nil
}

func (p *IAPTunnelProtocol) handleAck(msg []byte) ([]byte, error) {
	_, _, err := p.ExtractSubprotocolAck(msg)
	if err != nil {
		return nil, fmt.Errorf("unable to extract ack: %w", err)
	}
	return nil, nil
}

func (p *IAPTunnelProtocol) handleData(msg []byte) ([]byte, error) {
	data, _, err := p.ExtractData(msg)
	if err != nil {
		return nil, fmt.Errorf("unable to extract data: %w", err)
	}

	p.totalInboundLen += uint64(len(data))

	// // TODO: reimplement this properly or elsewhere
	// // Send ACK after receiving enough data
	// if p.totalInboundLen > 2*SUBPROTOCOL_MAX_DATA_FRAME_SIZE {
	// 	p.SendDataFrame(nil, p.CreateAckFrame(p.totalInboundLen))
	// 	// case p.dataChannel <- p.CreateAckFrame(p.totalInboundLen):
	// 	// default:
	// 	// }
	// }
	return data, nil
}

// ExtractSubprotocolTag extracts a 16-bit tag.
func (p *IAPTunnelProtocol) ExtractSubprotocolTag(data []byte) (uint16, []byte, error) {
	if len(data) < SUBPROTOCOL_TAG_LEN {
		return 0, nil, errors.New("incomplete data for tag")
	}
	tag := binary.BigEndian.Uint16(data[:SUBPROTOCOL_TAG_LEN])
	return tag, data[SUBPROTOCOL_TAG_LEN:], nil
}

// ExtractSubprotocolConnectSuccessSid extracts a 64-bit SID.
func (p *IAPTunnelProtocol) ExtractSubprotocolConnectSuccessSid(data []byte) (uint64, []byte, error) {
	if len(data) < 8 {
		return 0, nil, errors.New("incomplete data for connect success SID")
	}
	val := binary.BigEndian.Uint64(data[:8])
	return val, data[8:], nil
}

// ExtractSubprotocolAck extracts a 64-bit Ack.
func (p *IAPTunnelProtocol) ExtractSubprotocolAck(data []byte) (uint64, []byte, error) {
	if len(data) < 8 {
		return 0, nil, errors.New("incomplete data for ack")
	}
	val := binary.BigEndian.Uint64(data[:8])
	return val, data[8:], nil
}

// ExtractSubprotocolData extracts a length and then data of that length.
func (p *IAPTunnelProtocol) ExtractData(data []byte) ([]byte, []byte, error) {
	msgLen, remainder, err := extractUint32(data)
	if err != nil {
		return nil, nil, err
	}
	if uint32(len(remainder)) < msgLen {
		return nil, nil, errors.New("incomplete data for subprotocol payload")
	}
	payload := remainder[:msgLen]
	return payload, remainder[msgLen:], nil
}

func (p *IAPTunnelProtocol) CreateDataFrame(data []byte) []byte {
	frame := make([]byte, SUBPROTOCOL_TAG_LEN+4+len(data))
	binary.BigEndian.PutUint16(frame[0:], SUBPROTOCOL_TAG_DATA)
	binary.BigEndian.PutUint32(frame[SUBPROTOCOL_TAG_LEN:], uint32(len(data)))
	copy(frame[SUBPROTOCOL_TAG_LEN+4:], data)
	return frame
}

func (p *IAPTunnelProtocol) CreateAckFrame(length uint64) []byte {
	frame := make([]byte, SUBPROTOCOL_TAG_LEN+8)
	binary.BigEndian.PutUint16(frame[0:], SUBPROTOCOL_TAG_ACK)
	binary.BigEndian.PutUint64(frame[SUBPROTOCOL_TAG_LEN:], length)
	return frame
}

func (p *IAPTunnelProtocol) Errors() <-chan error {
	return p.errors
}
