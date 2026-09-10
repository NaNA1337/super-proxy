package discovery

import (
	"strings"
	"testing"
	"time"
)

func TestParseCSV(t *testing.T) {
	// A small dummy CSV representing VPN Gate response with valid Base64 OpenVPN configurations
	// Config 1: dev tun\nproto udp\nremote 192.168.1.1 1194\ncipher AES-128-CBC
	b64_1 := "ZGV2IHR1bgpwcm90byB1ZHAKcmVtb3RlIDE5Mi4xNjguMS4xIDExOTQKY2lwaGVyIEFFUy0xMjgtQ0JDCg=="
	// Config 2: dev tun\nproto tcp\nremote 192.168.1.2 443\ncipher AES-256-GCM
	b64_2 := "ZGV2IHR1bgpwcm90byB0Y3AKcmVtb3RlIDE5Mi4xNjguMS4yIDQ0MwpjaXBoZXIgQUVTLTI1Ni1HQ00K"

	csvData := "*vpn_servers\n" +
		"#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		"public-vpn-99,192.168.1.1,1000,10,10000000,Japan,JP,10,1234567,100,5000000,2,dummy,hello," + b64_1 + "\n" +
		"public-vpn-100,192.168.1.2,500,20,5000000,Korea Republic of,KR,5,123456,50,2500000,2,dummy,world," + b64_2 + "\n"

	nodes, err := parseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(nodes) != 2 {
		t.Fatalf("Expected 2 nodes, got %d", len(nodes))
	}

	n1 := nodes[0]
	if n1.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", n1.IP)
	}
	if n1.Country != "JP" {
		t.Errorf("Expected Country JP, got %s", n1.Country)
	}
	if n1.Score != 1000 {
		t.Errorf("Expected Score 1000, got %d", n1.Score)
	}
	if n1.EndpointPort != 1194 {
		t.Errorf("Expected EndpointPort 1194, got %d", n1.EndpointPort)
	}
	if n1.EndpointProto != "udp" {
		t.Errorf("Expected EndpointProto udp, got %s", n1.EndpointProto)
	}
	if n1.TotalTraffic != 5000000 {
		t.Errorf("Expected TotalTraffic 5000000, got %d", n1.TotalTraffic)
	}
	if n1.Operator != "dummy" {
		t.Errorf("Expected Operator dummy, got %s", n1.Operator)
	}

	n2 := nodes[1]
	if n2.EndpointPort != 443 {
		t.Errorf("Expected EndpointPort 443, got %d", n2.EndpointPort)
	}
	if n2.EndpointProto != "tcp" {
		t.Errorf("Expected EndpointProto tcp, got %s", n2.EndpointProto)
	}

	// Verify that raw OpenVPN is NOT populated on the Node struct (DB protection)
	if n1.OpenVPN != "" {
		t.Errorf("SECURITY LEAK: Node 1 has OpenVPN populated: %q", n1.OpenVPN)
	}
	if n2.OpenVPN != "" {
		t.Errorf("SECURITY LEAK: Node 2 has OpenVPN populated: %q", n2.OpenVPN)
	}

	// Verify that secrets ARE cached in-memory for runtime connection using node.ID
	c1, ok1 := GetOVPNSecret(n1.ID)
	if !ok1 || c1 != b64_1 {
		t.Errorf("Expected in-memory secret for node ID %s to match b64_1", n1.ID)
	}
	c2, ok2 := GetOVPNSecret(n2.ID)
	if !ok2 || c2 != b64_2 {
		t.Errorf("Expected in-memory secret for node ID %s to match b64_2", n2.ID)
	}
}

func TestSecretCache_TTLAndExplicitEviction(t *testing.T) {
	ClearOVPNSecretCache()
	defer ClearOVPNSecretCache()

	nodeID := "node-test-ttl-1"
	secret := "b64secret123"

	// 1. Store with short TTL (50ms)
	SetOVPNSecret(nodeID, secret, 50*time.Millisecond)

	val, ok := GetOVPNSecret(nodeID)
	if !ok || val != secret {
		t.Fatalf("Expected secret to be present before expiration, got val=%q, ok=%v", val, ok)
	}
	if size := OVPNSecretCacheSize(); size != 1 {
		t.Fatalf("Expected cache size 1, got %d", size)
	}

	// 2. Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// 3. Lazy eviction via GetOVPNSecret
	valExpired, okExpired := GetOVPNSecret(nodeID)
	if okExpired || valExpired != "" {
		t.Fatalf("Expected secret to be evicted after TTL expiry, got val=%q, ok=%v", valExpired, okExpired)
	}
	if size := OVPNSecretCacheSize(); size != 0 {
		t.Fatalf("Expected cache size 0 after lazy eviction, got %d", size)
	}

	// 4. Test explicit EvictExpiredSecrets
	nodeID2 := "node-test-ttl-2"
	SetOVPNSecret(nodeID2, secret, 20*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	evictedCount := EvictExpiredSecrets()
	if evictedCount != 1 {
		t.Fatalf("Expected 1 evicted secret, got %d", evictedCount)
	}

	// 5. Test explicit DeleteOVPNSecret
	nodeID3 := "node-test-explicit"
	SetOVPNSecret(nodeID3, secret, 1*time.Hour)
	DeleteOVPNSecret(nodeID3)
	valDeleted, okDeleted := GetOVPNSecret(nodeID3)
	if okDeleted || valDeleted != "" {
		t.Fatalf("Expected secret to be deleted by DeleteOVPNSecret")
	}
}

