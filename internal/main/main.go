package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	iap_tunnel "github.com/davidspek/terraform-provider-iap-tunnel/internal/iap-tunnel"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("Shutting down...")
		cancel()
	}()

	target := iap_tunnel.TunnelTarget{
		Project:   "prj-dl-dev-ooms-dev-2037",
		Zone:      "us-central1-a",
		Instance:  "bastion-vm",
		Interface: "nic0",
		Port:      6432,
	}
	manager := iap_tunnel.NewTunnelManager(target, nil)

	listenAddr := "localhost:6432"
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("Failed to listen on %s: %v\n", listenAddr, err)
		os.Exit(1)
	}
	defer lis.Close()

	go func() {
		if err := manager.Serve(ctx, lis); err != nil {
			fmt.Printf("Tunnel serve error: %v\n", err)
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	fmt.Println("Tunnel server exited")
}
