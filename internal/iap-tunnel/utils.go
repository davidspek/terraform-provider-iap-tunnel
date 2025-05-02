// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iap_tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// CreateWebSocketConnectURL builds the "connect" URL.
func CreateWebSocketConnectURL(t TunnelTarget, newWebSocket bool) (string, error) {
	if t.Project == "" || t.Port == 0 {
		return "", errors.New("missing required tunnel arguments: project or port")
	}
	u := createWebSocketURL(CONNECT_ENDPOINT, map[string]string{
		"project":      t.Project,
		"port":         strconv.Itoa(t.Port),
		"newWebsocket": fmt.Sprintf("%v", newWebSocket),
		"zone":         t.Zone,
		"instance":     t.Instance,
		"interface":    t.Interface,
		"region":       t.Region,
		"host":         t.Host,
		"group":        t.DestGroup,
		"network":      t.Network,
	}, t.URLOverride)
	return u, nil
}

// CreateWebSocketReconnectURL builds the "reconnect" URL.
func CreateWebSocketReconnectURL(t TunnelTarget, sid uint64, ackBytes uint64, newWebSocket bool) (string, error) {
	u := createWebSocketURL(RECONNECT_ENDPOINT, map[string]string{
		"sid":          fmt.Sprintf("%d", sid),
		"ack":          fmt.Sprintf("%d", ackBytes),
		"newWebsocket": fmt.Sprintf("%v", newWebSocket),
		"zone":         t.Zone,
		"region":       t.Region,
	}, t.URLOverride)
	return u, nil
}

// CreateSubprotocolAckFrame packs a TAG_ACK + uint64 ack.
func CreateSubprotocolAckFrame(ackBytes uint64) []byte {
	buf := make([]byte, 2+8)
	binary.BigEndian.PutUint16(buf[0:2], SUBPROTOCOL_TAG_ACK)
	binary.BigEndian.PutUint64(buf[2:], ackBytes)
	return buf
}

// CreateSubprotocolDataFrame packs a TAG_DATA + (data length) + data bytes.
func CreateSubprotocolDataFrame(data []byte) []byte {
	header := make([]byte, SUBPROTOCOL_HEADER_LEN)
	out := make([]byte, 0, len(header)+len(data))
	binary.BigEndian.PutUint16(header[0:2], SUBPROTOCOL_TAG_DATA)
	binary.BigEndian.PutUint32(header[2:6], uint32(len(data)))
	out = append(out, header...)
	return append(out, data...)
}

// ExtractSubprotocolTag extracts a 16-bit tag.
func ExtractSubprotocolTag(data []byte) (uint16, []byte, error) {
	if len(data) < SUBPROTOCOL_TAG_LEN {
		return 0, nil, errors.New("incomplete data for tag")
	}
	tag := binary.BigEndian.Uint16(data[:SUBPROTOCOL_TAG_LEN])
	return tag, data[SUBPROTOCOL_TAG_LEN:], nil
}

// ExtractSubprotocolConnectSuccessSid extracts a 64-bit SID.
func ExtractSubprotocolConnectSuccessSid(data []byte) (uint64, []byte, error) {
	if len(data) < 8 {
		return 0, nil, errors.New("incomplete data for connect success SID")
	}
	val := binary.BigEndian.Uint64(data[:8])
	return val, data[8:], nil
}

// ExtractSubprotocolAck extracts a 64-bit Ack.
func ExtractSubprotocolAck(data []byte) (uint64, []byte, error) {
	if len(data) < 8 {
		return 0, nil, errors.New("incomplete data for ack")
	}
	val := binary.BigEndian.Uint64(data[:8])
	return val, data[8:], nil
}

// ExtractSubprotocolData extracts a length and then data of that length.
func ExtractSubprotocolData(data []byte) ([]byte, []byte, error) {
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

// createWebSocketURL is analogous to _CreateWebSocketUrl in Python code.
func createWebSocketURL(endpoint string, query map[string]string, urlOverride string) string {
	useMTLS := false // Omit context-aware logic
	scheme := URL_SCHEME
	host := URL_HOST
	if useMTLS {
		host = MTLS_URL_HOST
	}
	pathRoot := URL_PATH_ROOT
	// If user provided an override
	if urlOverride != "" {
		parsed, err := url.Parse(urlOverride)
		if err == nil {
			if parsed.Scheme != "" {
				scheme = parsed.Scheme
			}
			if parsed.Host != "" {
				host = parsed.Host
			}
			if parsed.Path != "" && parsed.Path != "/" {
				pathRoot = parsed.Path
			}
		}
	}
	v := url.Values{}
	for k, val := range query {
		if val != "" {
			v.Add(k, val)
		}
	}
	thePath := pathRoot
	if thePath != "" && thePath[len(thePath)-1] != '/' {
		thePath += "/"
	}
	thePath += endpoint
	u := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     thePath,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// Helper extracting a 32-bit int from data.
func extractUint32(data []byte) (uint32, []byte, error) {
	if len(data) < 4 {
		return 0, nil, errors.New("incomplete data for uint32")
	}
	val := binary.BigEndian.Uint32(data[:4])
	return val, data[4:], nil
}
