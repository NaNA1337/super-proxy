package xray

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// PublicEndpoint defines a verified public-facing connectivity endpoint.
type PublicEndpoint struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	TLS      bool   `json:"tls"`
	Protocol string `json:"protocol"`
}

// Validate validates that the public endpoint conforms to production network policies.
func (ep *PublicEndpoint) Validate() error {
	if ep == nil {
		return fmt.Errorf("public endpoint is nil")
	}
	if err := ValidatePublicAddress(ep.Address); err != nil {
		return fmt.Errorf("invalid public endpoint address: %w", err)
	}
	if err := ValidateVlessPublicPort(ep.Port); err != nil {
		return fmt.Errorf("invalid public endpoint port: %w", err)
	}
	if ep.Network != "tcp" {
		return fmt.Errorf("invalid public endpoint network %q: must be \"tcp\"", ep.Network)
	}
	if ep.Protocol != "vless" {
		return fmt.Errorf("invalid public endpoint protocol %q: must be \"vless\"", ep.Protocol)
	}
	if !ep.TLS {
		return fmt.Errorf("invalid public endpoint security: TLS/Reality must be enabled")
	}
	return nil
}

// RealityClientProfile is the single unified profile representation used across all
// client configuration generators (VLESS URI, Clash Meta, Sing-box, Xray-core, Subscriptions).
type RealityClientProfile struct {
	Address         string `json:"address"`
	Port            int    `json:"port"`            // Strictly 443
	UUID            string `json:"uuid"`
	SNI             string `json:"sni"`
	Fingerprint     string `json:"fingerprint"`     // Strictly "chrome"
	PublicKey       string `json:"public_key"`
	ShortID         string `json:"short_id"`
	Flow            string `json:"flow"`            // Strictly "xtls-rprx-vision"
	Security        string `json:"security"`        // Strictly "reality"
	RealityTarget   string `json:"reality_target"`  // Strictly "<SNI>:443"
	Tag             string `json:"tag"`
	OutboundOnly443 bool   `json:"outbound_only_443"`
}

// Validate performs strict validation on the profile to prevent any invalid or non-standard configurations.
func (p *RealityClientProfile) Validate() error {
	if p == nil {
		return fmt.Errorf("reality client profile is nil")
	}
	if err := ValidatePublicAddress(p.Address); err != nil {
		return fmt.Errorf("profile address validation failed: %w", err)
	}
	if err := ValidateVlessPublicPort(p.Port); err != nil {
		return fmt.Errorf("profile public port validation failed: %w", err)
	}
	if _, err := uuid.Parse(p.UUID); err != nil {
		return fmt.Errorf("profile UUID %q is invalid: %w", p.UUID, err)
	}
	if err := ValidateRealitySNI(p.SNI); err != nil {
		return fmt.Errorf("profile SNI validation failed: %w", err)
	}
	if _, _, err := ValidateRealityDestination(p.RealityTarget, p.SNI); err != nil {
		return fmt.Errorf("profile reality target validation failed: %w", err)
	}
	if p.Fingerprint != DefaultRealityFP {
		return fmt.Errorf("invalid fingerprint %q: must be %q", p.Fingerprint, DefaultRealityFP)
	}
	if p.Flow != DefaultFlow {
		return fmt.Errorf("invalid flow %q: must be %q", p.Flow, DefaultFlow)
	}
	if p.Security != DefaultSecurity {
		return fmt.Errorf("invalid security %q: must be %q", p.Security, DefaultSecurity)
	}
	if strings.TrimSpace(p.PublicKey) == "" {
		return fmt.Errorf("profile public key cannot be empty")
	}
	if strings.TrimSpace(p.ShortID) == "" {
		return fmt.Errorf("profile short ID cannot be empty")
	}
	return nil
}

var (
	endpointMu             sync.RWMutex
	activeRuntimeEndpoint  *PublicEndpoint
)

// SetRuntimeVlessEndpoint safely stores the active running Xray inbound endpoint.
// Defaults empty Network to "tcp", Protocol to "vless", and validates the complete endpoint.
// Allocates an isolated copy internally to ensure immutability and thread safety.
func SetRuntimeVlessEndpoint(ep PublicEndpoint) error {
	if ep.Network == "" {
		ep.Network = "tcp"
	}
	if ep.Protocol == "" {
		ep.Protocol = "vless"
	}
	if err := ep.Validate(); err != nil {
		return fmt.Errorf("failed to register runtime endpoint: %w", err)
	}
	endpointMu.Lock()
	defer endpointMu.Unlock()
	cp := ep
	activeRuntimeEndpoint = &cp
	return nil
}

// GetRuntimeVlessEndpoint retrieves the currently running verified public endpoint.
// Returns an error if no verified runtime endpoint is currently active.
func GetRuntimeVlessEndpoint() (*PublicEndpoint, error) {
	endpointMu.RLock()
	defer endpointMu.RUnlock()
	if activeRuntimeEndpoint == nil {
		return nil, fmt.Errorf("no active Xray runtime endpoint registered")
	}
	if err := activeRuntimeEndpoint.Validate(); err != nil {
		return nil, fmt.Errorf("active runtime endpoint is invalid: %w", err)
	}
	cp := *activeRuntimeEndpoint
	return &cp, nil
}

// ClearRuntimeVlessEndpoint unregisters the active runtime endpoint (e.g., when Xray stops or crashes).
func ClearRuntimeVlessEndpoint() {
	endpointMu.Lock()
	defer endpointMu.Unlock()
	activeRuntimeEndpoint = nil
}
