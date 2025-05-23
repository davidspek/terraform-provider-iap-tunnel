// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net"
	"sync"

	tunnel "github.com/davidspek/go-iap-tunnel/pkg"
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
	listener net.Listener
	manager  *tunnel.TunnelManager
	cancel   context.CancelFunc
}
