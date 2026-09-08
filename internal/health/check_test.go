package health

import (
	"context"
	"net"
	"testing"
)

func TestCheckTunnelConnectivity_NoInterface(t *testing.T) {
	// Trying to bind to a non-existent interface should fail quickly
	ctx := context.Background()
	_, _, err := CheckTunnelConnectivity(ctx, "nonexistent0", "http://1.1.1.1")
	
	if err == nil {
		t.Error("Expected error when binding to non-existent interface, got nil")
	}

	// For a real interface, we would need root and an active connection.
	// Since tests run in various environments, we primarily test that the SO_BINDTODEVICE logic is invoked
	// and errors out correctly when invalid.
	
	// A common error for missing device is "no such device"
	if err != nil {
		if _, ok := err.(*net.OpError); !ok {
			t.Logf("Got error: %v", err)
		}
	}
}
