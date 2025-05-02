package iap_tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/coder/websocket"
)

type IAPTunnelProtocol struct{}

// TunnelProtocol defines the protocol-specific operations
type TunnelProtocol interface {
	ParseFrame(msg []byte) (uint16, []byte, error)
	SendDataFrame(conn *websocket.Conn, data []byte) error
	SendAckFrame(conn *websocket.Conn, length uint64) error
	SendFrame(conn *websocket.Conn, data []byte) error
	ExtractSubprotocolTag(data []byte) (uint16, []byte, error)
	ExtractSubprotocolConnectSuccessSid(data []byte) (uint64, []byte, error)
	ExtractSubprotocolAck(data []byte) (uint64, []byte, error)
	ExtractData(data []byte) ([]byte, []byte, error)
	CreateDataFrame(data []byte) []byte
	CreateAckFrame(length uint64) []byte
}

func NewIAPTunnelProtocol() TunnelProtocol {
	return &IAPTunnelProtocol{}
}

// SendDataFrame sends a data frame over the websocket connection using the IAP tunnel protocol.
func (p *IAPTunnelProtocol) SendDataFrame(conn *websocket.Conn, data []byte) error {
	frame := p.CreateDataFrame(data)
	err := p.SendFrame(conn, frame)
	if err != nil {
		return fmt.Errorf("failed to send data frame: %w", err)
	}
	fmt.Println("Sent data frame")
	return nil
}

// SendAckFrame sends an ACK frame over the websocket connection using the IAP tunnel protocol.
func (p *IAPTunnelProtocol) SendAckFrame(conn *websocket.Conn, length uint64) error {
	frame := p.CreateAckFrame(length)
	err := p.SendFrame(conn, frame)
	if err != nil {
		return fmt.Errorf("failed to send ACK frame: %w", err)
	}
	fmt.Println("Sent ACK frame")
	return nil
}

// SendFrame sends a frame frame over the websocket connection using the IAP tunnel protocol.
func (p *IAPTunnelProtocol) SendFrame(conn *websocket.Conn, data []byte) error {
	ctx := context.Background()
	// Use websocket.MessageBinary for binary frames
	writer, err := conn.Writer(ctx, websocket.MessageBinary)
	if err != nil {
		return fmt.Errorf("failed to get websocket writer: %w", err)
	}
	_, err = writer.Write(data)
	fmt.Println("Sent frame:", data)
	if err != nil {
		writer.Close()
		return fmt.Errorf("failed to write frame: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close websocket writer: %w", err)
	}
	return nil
}

func (p *IAPTunnelProtocol) ParseFrame(msg []byte) (uint16, []byte, error) {
	if err := p.ValidateMessage(msg); err != nil {
		return 0, nil, err
	}

	// tag, msg, err = p.ExtractSubprotocolTag(msg)
	// if err != nil {
	// 	return 0, fmt.Errorf("unable to extract subprotocol tag: %w", err)
	// }
	return p.ExtractSubprotocolTag(msg)
}

func (p *IAPTunnelProtocol) ValidateMessage(msg []byte) error {
	if len(msg) < SUBPROTOCOL_TAG_LEN {
		return errors.New("inbound message too short for subprotocol tag")
	}
	return nil
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
