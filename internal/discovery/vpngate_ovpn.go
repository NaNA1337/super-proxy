package discovery

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/NaNA1337/super-proxy/internal/models"
)

// SafeOpenVPNConfig holds validated, strictly allowlisted configuration directives.
type SafeOpenVPNConfig struct {
	Protocol        string
	Endpoints       []models.OpenVPNEndpoint
	PrimaryEndpoint models.OpenVPNEndpoint
	Dev             string
	DevType         string
	Cipher          string
	DataCiphers     string
	Auth            string
	RemoteCertTLS   string
	VerifyX509Name  string
	TLSVersionMin   string
	Nobind          bool
	InlineCA        string
	InlineCert      string
	InlineKey       string
}

// Disallowed directives that MUST be rejected immediately for security.
var disallowedDirectives = map[string]bool{
	"up":                         true,
	"down":                       true,
	"route-up":                   true,
	"route-pre-down":             true,
	"ipchange":                   true,
	"plugin":                     true,
	"tls-verify":                 true,
	"auth-user-pass-verify":      true,
	"client-connect":             true,
	"client-disconnect":          true,
	"learn-address":              true,
	"route":                      true,
	"route-ipv6":                 true,
	"management":                 true,
	"management-client":          true,
	"management-query-passwords": true,
	"script-security":            true,
	"system":                     true,
	"persist-key":                true,
	"persist-tun":                true,
	"setenv":                     true,
	"setenv-safe":                true,
	"exec":                       true,
	"user":                       true,
	"group":                      true,
	"chroot":                     true,
	"daemon":                     true,
	"socks-proxy":                true,
	"http-proxy":                 true,
}

// Allowed directives in untrusted VPN Gate configurations.
var allowedDirectives = map[string]bool{
	"client":               true,
	"proto":                true,
	"remote":               true,
	"port":                 true,
	"rport":                true,
	"dev":                  true,
	"dev-type":             true,
	"cipher":               true,
	"data-ciphers":         true,
	"auth":                 true,
	"remote-cert-tls":      true,
	"verify-x509-name":     true,
	"tls-version-min":      true,
	"nobind":               true,
	"resolv-retry":         true,
	"fast-io":              true,
	"ping":                 true,
	"ping-restart":         true,
	"keepalive":            true,
	"explicit-exit-notify": true,
	"auth-user-pass":       true,
	"verb":                 true,
}

var allowedInlineTags = map[string]bool{
	"ca":   true,
	"cert": true,
	"key":  true,
}

// ParseSafeOpenVPNConfig thoroughly validates and parses an untrusted OpenVPN config,
// enforcing strict allowlist controls, rejecting dangerous directives, extracting inline certs,
// and generating a safe canonical local configuration.
func ParseSafeOpenVPNConfig(b64Config string) (*SafeOpenVPNConfig, *models.OpenVPNConfigMeta, string, error) {
	trimmed := strings.TrimSpace(b64Config)
	if trimmed == "" {
		return nil, nil, "", errors.New("openvpn config data is empty")
	}

	// Base64 decode
	decodedBytes, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		var rawErr error
		decodedBytes, rawErr = base64.RawStdEncoding.DecodeString(trimmed)
		if rawErr != nil {
			return nil, nil, "", fmt.Errorf("failed to decode base64 openvpn config: %w", err)
		}
	}

	rawConfig := string(decodedBytes)
	if len(strings.TrimSpace(rawConfig)) == 0 {
		return nil, nil, "", errors.New("decoded openvpn config is empty")
	}

	safeCfg := &SafeOpenVPNConfig{
		Dev:     "tun",
		DevType: "tun",
		Nobind:  true,
	}

	meta := &models.OpenVPNConfigMeta{
		Endpoints: []models.OpenVPNEndpoint{},
	}

	scanner := bufio.NewScanner(strings.NewReader(rawConfig))
	var globalProto string
	var globalPort int
	type rawRemote struct {
		host            string
		port            int
		hasExplicitPort bool
		rawProto        string
	}
	var rawRemotes []rawRemote

	var currentInlineTag string
	var currentInlineContent strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle inline blocks: <ca>...</ca>, <cert>...</cert>, <key>...</key>
		if currentInlineTag != "" {
			closingTag := fmt.Sprintf("</%s>", currentInlineTag)
			if strings.EqualFold(line, closingTag) {
				content := currentInlineContent.String()
				switch currentInlineTag {
				case "ca":
					safeCfg.InlineCA = content
				case "cert":
					safeCfg.InlineCert = content
				case "key":
					safeCfg.InlineKey = content
				}
				currentInlineTag = ""
				currentInlineContent.Reset()
				continue
			}

			// Validate inline certificate line content (PEM lines, base64, header/footer)
			if err := validatePEMLine(line); err != nil {
				return nil, nil, "", fmt.Errorf("malicious or invalid content in <%s> block: %w", currentInlineTag, err)
			}

			currentInlineContent.WriteString(line)
			currentInlineContent.WriteString("\n")
			continue
		}

		// Check for opening inline block tag
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			tagName := strings.ToLower(strings.Trim(line, "<>/ \t"))
			if !allowedInlineTags[tagName] {
				return nil, nil, "", fmt.Errorf("unauthorized inline block tag <%s> rejected", tagName)
			}
			currentInlineTag = tagName
			currentInlineContent.Reset()
			continue
		}

		// Check for shell metacharacters in standard directives
		for _, ch := range []string{";", "&", "|", "`", "$", "(", ")", "{", "}", "\\"} {
			if strings.Contains(line, ch) {
				return nil, nil, "", fmt.Errorf("directive contains forbidden metacharacter %q: %s", ch, line)
			}
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		directive := strings.ToLower(fields[0])
		args := fields[1:]

		// Reject argument injection (directives starting with --)
		if strings.HasPrefix(directive, "--") {
			return nil, nil, "", fmt.Errorf("argument injection detected with prefix %q", directive)
		}

		// Reject disallowed directives
		if disallowedDirectives[directive] {
			return nil, nil, "", fmt.Errorf("security violation: disallowed directive %q is rejected", directive)
		}

		// Reject unknown directives
		if !allowedDirectives[directive] {
			return nil, nil, "", fmt.Errorf("unrecognized directive %q rejected by strict allowlist", directive)
		}

		switch directive {
		case "proto":
			if len(args) > 0 {
				p := normalizeProto(args[0])
				if p != "" {
					globalProto = p
					safeCfg.Protocol = p
				}
			}
		case "port", "rport":
			if len(args) > 0 {
				if p, err := strconv.Atoi(args[0]); err == nil && isValidPort(p) {
					globalPort = p
				}
			}
		case "remote":
			if len(args) == 0 {
				continue
			}
			host := sanitizeSafeString(args[0])
			port := -1
			hasExplicitPort := false
			rawProto := ""

			if len(args) >= 2 {
				if p, err := strconv.Atoi(args[1]); err == nil {
					port = p
					hasExplicitPort = true
				} else {
					rawProto = args[1]
				}
			}
			if len(args) >= 3 {
				if !hasExplicitPort {
					if p, err := strconv.Atoi(args[2]); err == nil {
						port = p
						hasExplicitPort = true
					}
				} else {
					rawProto = args[2]
				}
			}

			rawRemotes = append(rawRemotes, rawRemote{
				host:            host,
				port:            port,
				hasExplicitPort: hasExplicitPort,
				rawProto:        rawProto,
			})

		case "dev":
			if len(args) > 0 {
				d := sanitizeSafeString(args[0])
				if strings.HasPrefix(d, "tun") {
					safeCfg.Dev = d
					meta.Dev = d
				}
			}
		case "dev-type":
			if len(args) > 0 {
				dt := strings.ToLower(sanitizeSafeString(args[0]))
				if dt == "tun" {
					safeCfg.DevType = "tun"
					meta.DevType = "tun"
				}
			}
		case "cipher":
			if len(args) > 0 {
				safeCfg.Cipher = sanitizeSafeString(args[0])
				meta.Cipher = safeCfg.Cipher
			}
		case "data-ciphers":
			if len(args) > 0 {
				safeCfg.DataCiphers = sanitizeSafeString(strings.Join(args, " "))
				meta.DataCiphers = safeCfg.DataCiphers
			}
		case "auth":
			if len(args) > 0 {
				safeCfg.Auth = sanitizeSafeString(args[0])
				meta.Auth = safeCfg.Auth
			}
		case "remote-cert-tls":
			if len(args) > 0 {
				safeCfg.RemoteCertTLS = sanitizeSafeString(args[0])
				meta.RemoteCertTLS = safeCfg.RemoteCertTLS
			}
		case "verify-x509-name":
			if len(args) > 0 {
				safeCfg.VerifyX509Name = sanitizeSafeString(strings.Join(args, " "))
				meta.VerifyX509Name = safeCfg.VerifyX509Name
			}
		case "tls-version-min":
			if len(args) > 0 {
				safeCfg.TLSVersionMin = sanitizeSafeString(args[0])
			}
		case "nobind":
			safeCfg.Nobind = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, "", fmt.Errorf("error reading config stream: %w", err)
	}

	// Resolve and validate all remote endpoints
	for _, rr := range rawRemotes {
		if err := validateHost(rr.host); err != nil {
			continue
		}

		if rr.hasExplicitPort && !isValidPort(rr.port) {
			continue
		}

		resolvedPort := rr.port
		if !rr.hasExplicitPort || resolvedPort <= 0 {
			if globalPort > 0 {
				resolvedPort = globalPort
			} else {
				resolvedPort = 1194
			}
		}

		if !isValidPort(resolvedPort) {
			continue
		}

		var resolvedProto string
		if rr.rawProto != "" {
			norm := normalizeProto(rr.rawProto)
			if norm == "" {
				continue
			}
			resolvedProto = norm
		} else {
			if globalProto != "" {
				resolvedProto = globalProto
			} else {
				resolvedProto = "udp"
			}
		}

		if resolvedProto != "udp" && resolvedProto != "tcp" {
			continue
		}

		endpoint := models.OpenVPNEndpoint{
			Host:  rr.host,
			Port:  resolvedPort,
			Proto: resolvedProto,
		}
		meta.Endpoints = append(meta.Endpoints, endpoint)
		safeCfg.Endpoints = append(safeCfg.Endpoints, endpoint)
	}

	if len(meta.Endpoints) == 0 {
		return nil, nil, "", errors.New("no valid remote endpoints found in openvpn config")
	}

	meta.PrimaryEndpoint = meta.Endpoints[0]
	safeCfg.PrimaryEndpoint = meta.Endpoints[0]
	if safeCfg.Protocol == "" {
		safeCfg.Protocol = meta.PrimaryEndpoint.Proto
	}

	safeConfigStr := GenerateSafeOpenVPNConfig(safeCfg)
	return safeCfg, meta, safeConfigStr, nil
}

// ParseOpenVPNConfig decodes, validates, and generates a safe local OpenVPN configuration.
// Retains backward compatibility with callers expecting (string, *models.OpenVPNConfigMeta, error).
func ParseOpenVPNConfig(b64Config string) (string, *models.OpenVPNConfigMeta, error) {
	_, meta, safeConfigStr, err := ParseSafeOpenVPNConfig(b64Config)
	if err != nil {
		return "", nil, err
	}
	return safeConfigStr, meta, nil
}

// GenerateSafeOpenVPNConfig produces a clean, canonical OpenVPN configuration
// containing only strictly allowlisted, non-executable directives.
func GenerateSafeOpenVPNConfig(cfg *SafeOpenVPNConfig) string {
	var b strings.Builder
	b.WriteString("# Super-Proxy Safe Generated OpenVPN Configuration\n")
	b.WriteString("client\n")
	if cfg.Dev != "" {
		fmt.Fprintf(&b, "dev %s\n", cfg.Dev)
	} else {
		b.WriteString("dev tun\n")
	}
	b.WriteString("dev-type tun\n")

	proto := cfg.Protocol
	if proto == "" {
		proto = "udp"
	}
	fmt.Fprintf(&b, "proto %s\n", proto)

	for _, ep := range cfg.Endpoints {
		fmt.Fprintf(&b, "remote %s %d\n", ep.Host, ep.Port)
	}

	b.WriteString("nobind\n")
	b.WriteString("route-nopull\n") // Mandatory safe isolation: never overwrite host default route

	if cfg.Cipher != "" {
		fmt.Fprintf(&b, "cipher %s\n", cfg.Cipher)
	}
	if cfg.DataCiphers != "" {
		fmt.Fprintf(&b, "data-ciphers %s\n", cfg.DataCiphers)
	}
	if cfg.Auth != "" {
		fmt.Fprintf(&b, "auth %s\n", cfg.Auth)
	}
	if cfg.RemoteCertTLS != "" {
		fmt.Fprintf(&b, "remote-cert-tls %s\n", cfg.RemoteCertTLS)
	}
	if cfg.VerifyX509Name != "" {
		fmt.Fprintf(&b, "verify-x509-name %s\n", cfg.VerifyX509Name)
	}
	if cfg.TLSVersionMin != "" {
		fmt.Fprintf(&b, "tls-version-min %s\n", cfg.TLSVersionMin)
	}

	if cfg.InlineCA != "" {
		fmt.Fprintf(&b, "<ca>\n%s\n</ca>\n", strings.TrimSpace(cfg.InlineCA))
	}
	if cfg.InlineCert != "" {
		fmt.Fprintf(&b, "<cert>\n%s\n</cert>\n", strings.TrimSpace(cfg.InlineCert))
	}
	if cfg.InlineKey != "" {
		fmt.Fprintf(&b, "<key>\n%s\n</key>\n", strings.TrimSpace(cfg.InlineKey))
	}

	return b.String()
}

// GenerateSanitizedOpenVPNConfig produces a clean template config with all private keys redacted.
func GenerateSanitizedOpenVPNConfig(cfg *SafeOpenVPNConfig) string {
	var b strings.Builder
	b.WriteString("# Super-Proxy Sanitized OpenVPN Configuration Template\n")
	b.WriteString("client\n")
	if cfg.Dev != "" {
		fmt.Fprintf(&b, "dev %s\n", cfg.Dev)
	} else {
		b.WriteString("dev tun\n")
	}
	b.WriteString("dev-type tun\n")

	proto := cfg.Protocol
	if proto == "" {
		proto = "udp"
	}
	fmt.Fprintf(&b, "proto %s\n", proto)

	for _, ep := range cfg.Endpoints {
		fmt.Fprintf(&b, "remote %s %d\n", ep.Host, ep.Port)
	}

	b.WriteString("nobind\n")
	b.WriteString("route-nopull\n")

	if cfg.Cipher != "" {
		fmt.Fprintf(&b, "cipher %s\n", cfg.Cipher)
	}
	if cfg.DataCiphers != "" {
		fmt.Fprintf(&b, "data-ciphers %s\n", cfg.DataCiphers)
	}
	if cfg.Auth != "" {
		fmt.Fprintf(&b, "auth %s\n", cfg.Auth)
	}
	if cfg.RemoteCertTLS != "" {
		fmt.Fprintf(&b, "remote-cert-tls %s\n", cfg.RemoteCertTLS)
	}
	if cfg.VerifyX509Name != "" {
		fmt.Fprintf(&b, "verify-x509-name %s\n", cfg.VerifyX509Name)
	}
	if cfg.TLSVersionMin != "" {
		fmt.Fprintf(&b, "tls-version-min %s\n", cfg.TLSVersionMin)
	}

	if cfg.InlineCA != "" {
		b.WriteString("<ca>\n[CA CERTIFICATE REDACTED]\n</ca>\n")
	}
	if cfg.InlineCert != "" {
		b.WriteString("<cert>\n[CLIENT CERTIFICATE REDACTED]\n</cert>\n")
	}
	if cfg.InlineKey != "" {
		b.WriteString("<key>\n[PRIVATE KEY REDACTED]\n</key>\n")
	}

	return b.String()
}

// StripSecrets removes private keys and sensitive credentials from any OpenVPN config text.
func StripSecrets(cfgStr string) string {
	reKey := regexp.MustCompile(`(?s)<key>.*?</key>`)
	cfgStr = reKey.ReplaceAllString(cfgStr, "<key>\n[PRIVATE KEY REDACTED]\n</key>")

	reTLSAuth := regexp.MustCompile(`(?s)<tls-auth>.*?</tls-auth>`)
	cfgStr = reTLSAuth.ReplaceAllString(cfgStr, "<tls-auth>\n[TLS-AUTH REDACTED]\n</tls-auth>")

	reTLSCrypt := regexp.MustCompile(`(?s)<tls-crypt>.*?</tls-crypt>`)
	cfgStr = reTLSCrypt.ReplaceAllString(cfgStr, "<tls-crypt>\n[TLS-CRYPT REDACTED]\n</tls-crypt>")

	return cfgStr
}

func validatePEMLine(line string) error {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil
	}
	// Check standard PEM delimiters
	if strings.HasPrefix(trimmed, "-----BEGIN ") || strings.HasPrefix(trimmed, "-----END ") {
		return nil
	}
	// Check base64 chars
	for _, r := range trimmed {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+' && r != '/' && r != '=' {
			return fmt.Errorf("illegal character in certificate block: %q", r)
		}
	}
	return nil
}

func normalizeProto(p string) string {
	cleaned := strings.ToLower(strings.TrimSpace(p))
	switch cleaned {
	case "udp", "udp4", "udp6":
		return "udp"
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp-server":
		return "tcp"
	default:
		return ""
	}
}

func isValidPort(p int) bool {
	return p >= 1 && p <= 65535
}

func validateHost(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	if len(host) > 255 {
		return errors.New("host exceeds 255 characters")
	}
	for _, r := range host {
		if unicode.IsControl(r) {
			return errors.New("host contains control characters")
		}
		switch r {
		case ';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\t', '"', '\'', '\\', ' ':
			return fmt.Errorf("host contains forbidden character: %q", r)
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("invalid hostname label length")
		}
		for i, c := range label {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' {
				return fmt.Errorf("invalid character %q in hostname label", c)
			}
			if (i == 0 || i == len(label)-1) && (c == '-' || c == '_') {
				return errors.New("hostname label cannot begin or end with hyphen/underscore")
			}
		}
	}
	return nil
}

func sanitizeSafeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsControl(r) && r != ';' && r != '&' && r != '|' && r != '`' && r != '$' && r != '"' && r != '\'' && r != '\\' && r != '<' && r != '>' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
