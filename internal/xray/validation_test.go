package xray

import (
	"testing"

	"github.com/google/uuid"
)

func TestValidatePublicPort(t *testing.T) {
	passPorts := []int{60000, 60001, 60500, 61000}
	for _, port := range passPorts {
		if err := ValidatePublicPort(port); err != nil {
			t.Errorf("expected port %d to PASS, got error: %v", port, err)
		}
	}

	failPorts := []int{59999, 61001, 443, 80, 1080, 8080, 0, -1, 65535}
	for _, port := range failPorts {
		if err := ValidatePublicPort(port); err == nil {
			t.Errorf("expected port %d to FAIL, but passed", port)
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
		Port:            60001,
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

	// Reject port 443
	pPort443 := validProfile
	pPort443.Port = 443
	if err := pPort443.Validate(); err == nil {
		t.Errorf("expected profile with port 443 to fail")
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

	// Registering port 443 must fail validation
	badEp := PublicEndpoint{
		Address:  "203.0.113.1",
		Port:     443,
		Network:  "tcp",
		TLS:      true,
		Protocol: "vless",
	}
	if err := SetRuntimeVlessEndpoint(badEp); err == nil {
		t.Errorf("expected registering port 443 to fail")
	}

	// Registering valid port 60001
	goodEp := PublicEndpoint{
		Address:  "203.0.113.1",
		Port:     60001,
		Network:  "tcp",
		TLS:      true,
		Protocol: "vless",
	}
	if err := SetRuntimeVlessEndpoint(goodEp); err != nil {
		t.Fatalf("failed to register good runtime endpoint: %v", err)
	}

	retrieved, err := GetRuntimeVlessEndpoint()
	if err != nil {
		t.Fatalf("failed to retrieve registered endpoint: %v", err)
	}
	if retrieved.Port != 60001 || retrieved.Address != "203.0.113.1" {
		t.Errorf("retrieved endpoint mismatch: %+v", retrieved)
	}

	ClearRuntimeVlessEndpoint()
	if _, err := GetRuntimeVlessEndpoint(); err == nil {
		t.Fatalf("expected error after clearing runtime endpoint")
	}
}
