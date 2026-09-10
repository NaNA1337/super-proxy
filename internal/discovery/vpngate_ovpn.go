package discovery

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/NaNA1337/super-proxy/internal/models"
)

// ParseOpenVPNConfig decodes and thoroughly parses an untrusted Base64 OpenVPN configuration.
// It extracts all remote endpoints preserving order, normalizes protocol, extracts cryptographic
// directives, and strictly validates against malicious or malformed inputs.
func ParseOpenVPNConfig(b64Config string) (string, *models.OpenVPNConfigMeta, error) {
	trimmed := strings.TrimSpace(b64Config)
	if trimmed == "" {
		return "", nil, errors.New("openvpn config data is empty")
	}

	// Base64 decode
	decodedBytes, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		// Attempt RawStdEncoding in case padding is missing
		var rawErr error
		decodedBytes, rawErr = base64.RawStdEncoding.DecodeString(trimmed)
		if rawErr != nil {
			return "", nil, fmt.Errorf("failed to decode base64 openvpn config: %w", err)
		}
	}

	rawConfig := string(decodedBytes)
	if len(strings.TrimSpace(rawConfig)) == 0 {
		return "", nil, errors.New("decoded openvpn config is empty")
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

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		directive := strings.ToLower(fields[0])
		args := fields[1:]

		switch directive {
		case "proto":
			if len(args) > 0 {
				p := normalizeProto(args[0])
				if p != "" {
					globalProto = p
				}
			}
		case "port":
			if len(args) > 0 {
				if p, err := strconv.Atoi(args[0]); err == nil && isValidPort(p) {
					globalPort = p
				}
			}
		case "remote":
			if len(args) == 0 {
				continue
			}
			host := args[0]
			port := -1
			hasExplicitPort := false
			rawProto := ""

			if len(args) >= 2 {
				if p, err := strconv.Atoi(args[1]); err == nil {
					port = p
					hasExplicitPort = true
				} else {
					// Sometimes remote has syntax: remote host [proto]
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
			if len(args) > 0 && meta.Dev == "" {
				meta.Dev = sanitizeSafeString(args[0])
			}
		case "dev-type":
			if len(args) > 0 && meta.DevType == "" {
				meta.DevType = strings.ToLower(sanitizeSafeString(args[0]))
			}
		case "cipher":
			if len(args) > 0 && meta.Cipher == "" {
				meta.Cipher = sanitizeSafeString(args[0])
			}
		case "data-ciphers":
			if len(args) > 0 && meta.DataCiphers == "" {
				meta.DataCiphers = sanitizeSafeString(strings.Join(args, " "))
			}
		case "auth":
			if len(args) > 0 && meta.Auth == "" {
				meta.Auth = sanitizeSafeString(args[0])
			}
		case "remote-cert-tls":
			if len(args) > 0 && meta.RemoteCertTLS == "" {
				meta.RemoteCertTLS = sanitizeSafeString(args[0])
			}
		case "verify-x509-name":
			if len(args) > 0 && meta.VerifyX509Name == "" {
				meta.VerifyX509Name = sanitizeSafeString(strings.Join(args, " "))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("error reading config stream: %w", err)
	}

	// Resolve and validate all remote endpoints
	for _, rr := range rawRemotes {
		if err := validateHost(rr.host); err != nil {
			// Skip or reject malicious/invalid host
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
				resolvedPort = 1194 // OpenVPN standard default port
			}
		}

		if !isValidPort(resolvedPort) {
			continue
		}

		var resolvedProto string
		if rr.rawProto != "" {
			norm := normalizeProto(rr.rawProto)
			if norm == "" {
				// Explicitly specified proto is invalid; reject this remote
				continue
			}
			resolvedProto = norm
		} else {
			if globalProto != "" {
				resolvedProto = globalProto
			} else {
				resolvedProto = "udp" // OpenVPN standard default protocol
			}
		}

		if resolvedProto != "udp" && resolvedProto != "tcp" {
			continue
		}

		meta.Endpoints = append(meta.Endpoints, models.OpenVPNEndpoint{
			Host:  rr.host,
			Port:  resolvedPort,
			Proto: resolvedProto,
		})
	}

	if len(meta.Endpoints) == 0 {
		return "", nil, errors.New("no valid remote endpoints found in openvpn config")
	}

	// Primary endpoint is the first valid remote in config order
	meta.PrimaryEndpoint = meta.Endpoints[0]

	return rawConfig, meta, nil
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

// validateHost ensures the host string contains only safe domain/IP characters.
// Blocks shell interpolation, control chars, semicolons, backticks, quotes, etc.
func validateHost(host string) error {
	if host == "" {
		return errors.New("empty host")
	}

	// Must not exceed max hostname length
	if len(host) > 255 {
		return errors.New("host exceeds 255 characters")
	}

	// Check for forbidden characters
	for _, r := range host {
		if unicode.IsControl(r) {
			return errors.New("host contains control characters")
		}
		// Explicit forbidden characters for untrusted shell safety
		switch r {
		case ';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\t', '"', '\'', '\\', ' ':
			return fmt.Errorf("host contains forbidden character: %q", r)
		}
	}

	// Check if valid IP address
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}

	// Check if valid DNS hostname
	// RFC 1123: labels separated by dots, 1-63 chars each, alphanumeric + hyphen
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
		if !unicode.IsControl(r) && r != ';' && r != '&' && r != '|' && r != '`' && r != '$' && r != '"' && r != '\'' && r != '\\' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
