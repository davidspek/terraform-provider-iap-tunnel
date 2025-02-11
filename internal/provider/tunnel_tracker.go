// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"sync"

	iap_tunnel "github.com/davidspek/terraform-provider-iap-tunnel/internal/iap-tunnel"
)

type TunnelTracker struct {
	mu      sync.Mutex
	tunnels map[string]*TunnelInfo
}

func NewTunnelTracker() *TunnelTracker {
	return &TunnelTracker{
		tunnels: map[string]*TunnelInfo{},
	}
}

func (t *TunnelTracker) Add(name string, info *TunnelInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.tunnels[name] = info
}

func (t *TunnelTracker) Get(name string) *TunnelInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.tunnels[name]
}

func (t *TunnelTracker) Remove(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.tunnels, name)
}

type TunnelInfo struct {
	manager *iap_tunnel.TunnelManager
	cancel  context.CancelFunc
	// conn     *websocket.Conn
	// listener net.Listener
}
