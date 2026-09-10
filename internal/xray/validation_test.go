package xray

import (
	"testing"

	"github.com/google/uuid"
)

func TestValidateVlessPublicPort(t *testing.T) {
	// 443 strictly PASS
	if err := ValidateVlessPublicPort(443); err != nil {
		t.Errorf("expected port 443 to PASS, got error: %v", err)
	}

	// All other ports strictly FAIL
	failPorts := []int{80, 1080, 8080, 60000, 60001, 60500, 61000, 0, -1, 65535}
	for _, port := range failPorts {
		if err := ValidateVlessPublicPort(port); err == nil {
			t.Errorf("expected VLESS port %d to FAIL, but passed", port)
		}
	}
}

func TestValidateManagementPort(t *testing.T) {
	// 60000 strictly PASS
	if err := ValidateManagementPort(60000); err != nil {
		t.Errorf("expected management port 60000 to PASS, got error: %v", err)
	}

	// 443 and others strictly FAIL as management
	failPorts := []int{443, 80, 1080, 8080, 60001, 61000, 0, -1, 65535}
	for _, port := range failPorts {
		if err := ValidateManagementPort(port); err == nil {
			t.Errorf("expected management port %d to FAIL, but passed", port)
		}
	}
}

func TestValidatePublicAddress(t *testing.T) {
	passAddrs := []string{
		"node.super-proxy.net",
		"example.com",
		"203.0.113.1",
		"198.51.100.25",
		"sub.domain.co.jp",
	}
	for _, addr := range passAddrs {
		if err := ValidatePublicAddress(addr); err != nil {
			t.Errorf("expected public address %q to PASS, got error: %v", addr, err)
		}
	}

	failAddrs := []string{
		"",
		"   ",
		"localhost",
		"127.0.0.1",
		"127.0.0.2",
		"0.0.0.0",
		"::",
		"::1",
		"https://node.super-proxy.net",
		"http://node.super-proxy.net",
		"node.super-proxy.net:443",
		"node.super-proxy.net/path",
		"user@node.super-proxy.net",
		"invalid_domain_name",
	}
	for _, addr := range failAddrs {
		if err := ValidatePublicAddress(addr); err == nil {
			t.Errorf("expected public address %q to FAIL, but passed", addr)
		}
	}
}

func TestValidateRealitySNI(t *testing.T) {
	passSNIs := []string{
		"www.microsoft.com",
		"microsoft.com",
		"azure.microsoft.com",
		"portal.azure.com",
	}
	for _, sni := range passSNIs {
		if err := ValidateRealitySNI(sni); err != nil {
			t.Errorf("expected SNI %q to PASS, got error: %v", sni, err)
		}
	}

	failSNIs := []string{
		"",
		"   ",
		"localhost",
		"127.0.0.1",
		"::1",
		"192.168.1.1",
		"https://www.microsoft.com",
		"http://www.microsoft.com",
		"www.microsoft.com:443",
		"www.microsoft.com/path",
		"user@www.microsoft.com",
		"www.microsoft.com?query=1",
		"invalid_domain.com",
	}
	for _, sni := range failSNIs {
		if err := ValidateRealitySNI(sni); err == nil {
			t.Errorf("expected SNI %q to FAIL, but passed", sni)
		}
	}
}

func TestValidateRealityDestination(t *testing.T) {
	// Valid destination matching SNI
	host, port, err := ValidateRealityDestination("www.microsoft.com:443", "www.microsoft.com")
	if err != nil {
		t.Fatalf("expected valid destination to PASS, got: %v", err)
	}
	if host != "www.microsoft.com" || port != 443 {
		t.Errorf("unexpected host/port: %s:%d", host, port)
	}

	// Non-443 port must fail
	if _, _, err := ValidateRealityDestination("www.microsoft.com:8443", "www.microsoft.com"); err == nil {
		t.Errorf("expected non-443 port to fail")
	}

	// SNI mismatch must fail
	if _, _, err := ValidateRealityDestination("www.google.com:443", "www.microsoft.com"); err == nil {
		t.Errorf("expected SNI mismatch to fail")
	}

	// IP destination must fail
	if _, _, err := ValidateRealityDestination("127.0.0.1:443", "127.0.0.1"); err == nil {
		t.Errorf("expected IP destination to fail")
	}
}

func TestRealityClientProfile_Validate(t *testing.T) {
	validProfile := RealityClientProfile{
		Address:         "203.0.113.1",
		Port:            443, // Strictly 443
		UUID:            uuid.New().String(),
		SNI:             "www.microsoft.com",
		Fingerprint:     "chrome",
		PublicKey:       "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortID:         "0123456789abcdef",
		Flow:            "xtls-rprx-vision",
		Security:        "reality",
		RealityTarget:   "www.microsoft.com:443",
		Tag:             "Super-Proxy-VLESS",
		OutboundOnly443: true,
	}

	if err := validProfile.Validate(); err != nil {
		t.Fatalf("expected valid profile to pass, got: %v", err)
	}

	// Reject port 60000
	pPort60000 := validProfile
	pPort60000.Port = 60000
	if err := pPort60000.Validate(); err == nil {
		t.Errorf("expected profile with port 60000 to fail")
	}

	// Reject port 60001
	pPort60001 := validProfile
	pPort60001.Port = 60001
	if err := pPort60001.Validate(); err == nil {
		t.Errorf("expected profile with port 60001 to fail")
	}

	// Reject localhost address
	pLocalhost := validProfile
	pLocalhost.Address = "127.0.0.1"
	if err := pLocalhost.Validate(); err == nil {
		t.Errorf("expected profile with localhost address to fail")
	}

	// Reject non-chrome fingerprint
	pFp := validProfile
	pFp.Fingerprint = "firefox"
	if err := pFp.Validate(); err == nil {
		t.Errorf("expected non-chrome fingerprint to fail")
	}

	// Reject non-vision flow
	pFlow := validProfile
	pFlow.Flow = "xtls-rprx-origin"
	if err := pFlow.Validate(); err == nil {
		t.Errorf("expected non-vision flow to fail")
	}

	// Reject empty public key
	pKey := validProfile
	pKey.PublicKey = ""
	if err := pKey.Validate(); err == nil {
		t.Errorf("expected empty public key to fail")
	}
}

func TestRuntimeEndpointStore(t *testing.T) {
	ClearRuntimeVlessEndpoint()

	// Initially empty -> returns error
	if _, err := GetRuntimeVlessEndpoint(); err == nil {
		t.Fatalf("expected error when no runtime endpoint registered")
	}

	// Registering port 60001 must fail validation
	badPortEp := PublicEndpoint{
		Address:  "203.0.113.1",
		Port:     60001,
		Network:  "tcp",
		TLS:      true,
		Protocol: "vless",
	}
	if err := SetRuntimeVlessEndpoint(badPortEp); err == nil {
		t.Errorf("expected registering port 60001 to fail")
	}

	// Registering localhost address must fail validation
	badAddrEp := PublicEndpoint{
		Address:  "127.0.0.1",
		Port:     443,
		Network:  "tcp",
		TLS:      true,
		Protocol: "vless",
	}
	if err := SetRuntimeVlessEndpoint(badAddrEp); err == nil {
		t.Errorf("expected registering loopback address 127.0.0.1 to fail")
	}

	// Registering valid endpoint: port 443 and public address
	goodEp := PublicEndpoint{
		Address:  "203.0.113.1",
		Port:     443,
		Network:  "tcp",
		TLS:      true,
		Protocol: "vless",
	}
	if err := SetRuntimeVlessEndpoint(goodEp); err != nil {
		t.Fatalf("failed to register good runtime endpoint: %v", err)
	}

	// Registering invalid network must fail validation
	badNetEp := goodEp
	badNetEp.Network = "udp"
	if err := SetRuntimeVlessEndpoint(badNetEp); err == nil {
		t.Errorf("expected registering udp network to fail")
	}

	// Registering invalid protocol must fail validation
	badProtoEp := goodEp
	badProtoEp.Protocol = "trojan"
	if err := SetRuntimeVlessEndpoint(badProtoEp); err == nil {
		t.Errorf("expected registering trojan protocol to fail")
	}

	// Registering without TLS must fail validation
	badTlsEp := goodEp
	badTlsEp.TLS = false
	if err := SetRuntimeVlessEndpoint(badTlsEp); err == nil {
		t.Errorf("expected registering without TLS to fail")
	}

	retrieved, err := GetRuntimeVlessEndpoint()
	if err != nil {
		t.Fatalf("failed to retrieve registered endpoint: %v", err)
	}
	if retrieved.Port != 443 || retrieved.Address != "203.0.113.1" || retrieved.Network != "tcp" || retrieved.Protocol != "vless" || !retrieved.TLS {
		t.Errorf("retrieved endpoint mismatch: %+v", retrieved)
	}

	// Invariant 4: Clear must be idempotent
	ClearRuntimeVlessEndpoint()
	ClearRuntimeVlessEndpoint()
	if _, err := GetRuntimeVlessEndpoint(); err == nil {
		t.Fatalf("expected error after clearing runtime endpoint")
	}
}
