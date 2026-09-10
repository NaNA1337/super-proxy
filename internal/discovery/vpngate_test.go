package discovery

import (
	"strings"
	"testing"
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

	// Verify that secrets ARE cached in-memory for runtime connection
	c1, ok1 := GetOVPNSecret("192.168.1.1")
	if !ok1 || c1 != b64_1 {
		t.Errorf("Expected in-memory secret for 192.168.1.1 to match b64_1")
	}
	c2, ok2 := GetOVPNSecret("192.168.1.2")
	if !ok2 || c2 != b64_2 {
		t.Errorf("Expected in-memory secret for 192.168.1.2 to match b64_2")
	}
}
