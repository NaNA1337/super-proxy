package discovery

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseOpenVPNConfig_ValidSingleRemote(t *testing.T) {
	cfg := `
dev tun
proto udp
remote 198.51.100.1 1194
cipher AES-256-CBC
auth SHA256
remote-cert-tls server
`
	b64 := base64.StdEncoding.EncodeToString([]byte(cfg))

	raw, meta, err := ParseOpenVPNConfig(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != cfg {
		t.Fatalf("raw config mismatch")
	}
	if meta.Dev != "tun" {
		t.Errorf("expected dev tun, got %s", meta.Dev)
	}
	if meta.Cipher != "AES-256-CBC" {
		t.Errorf("expected cipher AES-256-CBC, got %s", meta.Cipher)
	}
	if meta.Auth != "SHA256" {
		t.Errorf("expected auth SHA256, got %s", meta.Auth)
	}
	if meta.RemoteCertTLS != "server" {
		t.Errorf("expected remote-cert-tls server, got %s", meta.RemoteCertTLS)
	}
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(meta.Endpoints))
	}
	ep := meta.Endpoints[0]
	if ep.Host != "198.51.100.1" || ep.Port != 1194 || ep.Proto != "udp" {
		t.Errorf("unexpected endpoint: %+v", ep)
	}
	if meta.PrimaryEndpoint != ep {
		t.Errorf("primary endpoint mismatch: %+v vs %+v", meta.PrimaryEndpoint, ep)
	}
}

func TestParseOpenVPNConfig_MultipleRemotesAndPriority(t *testing.T) {
	cfg := `
dev tun0
dev-type tun
proto tcp-client
port 443
remote 198.51.100.2
remote vpn.example.com 8443
remote 2001:db8::1 1194 udp
cipher AES-128-GCM
data-ciphers AES-256-GCM:AES-128-GCM
verify-x509-name vpn-server name
`
	b64 := base64.StdEncoding.EncodeToString([]byte(cfg))

	_, meta, err := ParseOpenVPNConfig(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if meta.DevType != "tun" {
		t.Errorf("expected dev-type tun, got %s", meta.DevType)
	}
	if meta.DataCiphers != "AES-256-GCM:AES-128-GCM" {
		t.Errorf("expected data-ciphers, got %s", meta.DataCiphers)
	}
	if meta.VerifyX509Name != "vpn-server name" {
		t.Errorf("expected verify-x509-name, got %s", meta.VerifyX509Name)
	}

	if len(meta.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(meta.Endpoints))
	}

	// 1st remote: 198.51.100.2 -> inherits global port 443, global proto tcp
	if meta.Endpoints[0].Host != "198.51.100.2" || meta.Endpoints[0].Port != 443 || meta.Endpoints[0].Proto != "tcp" {
		t.Errorf("remote 1 mismatch: %+v", meta.Endpoints[0])
	}
	// 2nd remote: vpn.example.com 8443 -> inherits global proto tcp
	if meta.Endpoints[1].Host != "vpn.example.com" || meta.Endpoints[1].Port != 8443 || meta.Endpoints[1].Proto != "tcp" {
		t.Errorf("remote 2 mismatch: %+v", meta.Endpoints[1])
	}
	// 3rd remote: 2001:db8::1 1194 udp -> explicit port 1194 and proto udp
	if meta.Endpoints[2].Host != "2001:db8::1" || meta.Endpoints[2].Port != 1194 || meta.Endpoints[2].Proto != "udp" {
		t.Errorf("remote 3 mismatch: %+v", meta.Endpoints[2])
	}

	// Primary endpoint must be the first in configuration order
	if meta.PrimaryEndpoint != meta.Endpoints[0] {
		t.Errorf("expected primary endpoint to be endpoints[0]")
	}
}

func TestParseOpenVPNConfig_RejectionCases(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		errMsg string
	}{
		{
			name:   "empty config",
			input:  "",
			errMsg: "openvpn config data is empty",
		},
		{
			name:   "invalid base64",
			input:  "not_base64_!@#$%",
			errMsg: "failed to decode base64",
		},
		{
			name:   "empty decoded string",
			input:  base64.StdEncoding.EncodeToString([]byte("   \n\n\t  ")),
			errMsg: "decoded openvpn config is empty",
		},
		{
			name:   "missing remote directive",
			input:  base64.StdEncoding.EncodeToString([]byte("dev tun\nproto udp\nport 1194\n")),
			errMsg: "no valid remote endpoints found",
		},
		{
			name:   "invalid port",
			input:  base64.StdEncoding.EncodeToString([]byte("remote 1.2.3.4 999999\n")),
			errMsg: "no valid remote endpoints found",
		},
		{
			name:   "invalid proto",
			input:  base64.StdEncoding.EncodeToString([]byte("remote 1.2.3.4 1194 sctp\n")),
			errMsg: "no valid remote endpoints found",
		},
		{
			name:   "malicious shell injection host",
			input:  base64.StdEncoding.EncodeToString([]byte("remote 1.2.3.4;rm -rf / 1194\n")),
			errMsg: "no valid remote endpoints found",
		},
		{
			name:   "malicious backtick host",
			input:  base64.StdEncoding.EncodeToString([]byte("remote `whoami`.evil.com 1194\n")),
			errMsg: "no valid remote endpoints found",
		},
		{
			name:   "malicious pipe host",
			input:  base64.StdEncoding.EncodeToString([]byte("remote 1.2.3.4|cat /etc/passwd 1194\n")),
			errMsg: "no valid remote endpoints found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseOpenVPNConfig(tc.input)
			if err == nil {
				t.Fatalf("expected error for case %q, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("expected error to contain %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}
