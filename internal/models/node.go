package models

import (
	"time"
)

const (
	StatusNew               = "NEW"
	StatusDiscovered        = "DISCOVERED"
	StatusReputationChecked = "REPUTATION_CHECKED"
	StatusConnecting        = "CONNECTING"
	StatusHealthCheck       = "HEALTH_CHECK"
	StatusSpeedTest         = "SPEED_TEST"
	StatusHealthy           = "HEALTHY"
	StatusQualified         = "QUALIFIED"
	StatusStandby           = "STANDBY"
	StatusActive            = "ACTIVE"
	StatusDraining          = "DRAINING"
	StatusFailed            = "FAILED"
	StatusCooldown          = "COOLDOWN"
	StatusDead              = "DEAD"
	StatusStale             = "STALE"
)

// OpenVPNEndpoint represents a parsed remote destination from OpenVPN config.
type OpenVPNEndpoint struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "udp" or "tcp"
}

// OpenVPNConfigMeta encapsulates structured OpenVPN configuration directives.
type OpenVPNConfigMeta struct {
	Endpoints       []OpenVPNEndpoint `json:"endpoints"`
	PrimaryEndpoint OpenVPNEndpoint   `json:"primary_endpoint"`
	Dev             string            `json:"dev"`
	DevType         string            `json:"dev_type"`
	Cipher          string            `json:"cipher"`
	DataCiphers     string            `json:"data_ciphers"`
	Auth            string            `json:"auth"`
	RemoteCertTLS   string            `json:"remote_cert_tls"`
	VerifyX509Name  string            `json:"verify_x509_name"`
}

// Node represents a VPN Gate node
type Node struct {
	ID        string    `gorm:"primaryKey" json:"id"` // Node identifier: IP or IP:Port
	HostName  string    `json:"hostname"`
	IP        string    `gorm:"index" json:"ip"`
	Score     int       `json:"score"` // Original VPN Gate score
	Country   string    `gorm:"index" json:"country"`
	CountryL  string    `json:"country_long"`
	Sessions  int       `json:"sessions"`
	Uptime    int64     `json:"uptime"` // in milliseconds
	Users     int       `json:"users"`
	Message   string    `json:"message"`
	OpenVPN   string    `json:"openvpn_config_base64"`

	// VPN Gate Discovery metadata
	TotalTraffic int64  `json:"total_traffic"`
	LogType      string `json:"log_type"`
	Operator     string `json:"operator"`

	// Structured OpenVPN endpoint information
	EndpointHost  string `gorm:"index" json:"endpoint_host"`
	EndpointPort  int    `gorm:"index" json:"endpoint_port"`
	EndpointProto string `json:"endpoint_proto"`
	OpenVPNConfig string `json:"openvpn_config"` // Decoded .ovpn config
	EndpointsJSON string `json:"endpoints_json"` // JSON-encoded []OpenVPNEndpoint
	
	Status       string    `gorm:"index" json:"status"` // NEW, DISCOVERED, ACTIVE, FAILED, COOLDOWN, DEAD
	LastSeen     time.Time `json:"last_seen"`
	FirstSeen    time.Time `json:"first_seen"`
	FailCount    int       `json:"fail_count"`

	// Separated concerns using GORM embedded structs
	Reputation  ReputationMetrics  `gorm:"embedded;embeddedPrefix:rep_" json:"reputation"`
	NetClass    NetworkClass       `gorm:"embedded;embeddedPrefix:net_" json:"network_class"`
	Performance PerformanceMetrics `gorm:"embedded;embeddedPrefix:perf_" json:"performance"`
}

type ReputationMetrics struct {
	Status        string `json:"status"` // GOOD, BAD, UNKNOWN
	IsBlacklisted bool   `json:"is_blacklisted"`
	FraudScore    int    `json:"fraud_score"`
	ProviderName  string `json:"provider_name"`
	Details       string `json:"details"`
}

type NetworkClass struct {
	ASN          string `json:"asn"`
	ISP          string `json:"isp"`
	Organization string `json:"organization"`
	NetworkType  string `json:"network_type"` // e.g. "broadband", "hosting", "residential"
	IsVPN        bool   `json:"is_vpn"`
	IsProxy      bool   `json:"is_proxy"`
	IsTor        bool   `json:"is_tor"`
	IsHosting    bool   `json:"is_hosting"`
}

type PerformanceMetrics struct {
	RTT              int       `json:"rtt_ms"`              // Round-trip time in milliseconds
	Throughput       int64     `json:"throughput_bps"`      // Aggregate throughput in bps
	DownloadSpeed    int64     `json:"download_bps"`        // Download throughput
	UploadSpeed      int64     `json:"upload_bps"`          // Upload throughput
	UploadStatus     string    `json:"upload_status"`       // "AVAILABLE", "UNAVAILABLE", "FAILED"
	SpeedStatus      string    `json:"speed_status"`        // "AVAILABLE", "UNAVAILABLE", "NOT_MEASURED"
	PacketLoss       float64   `json:"packet_loss_pct"`     // Packet loss percentage (-1 if unavailable)
	PacketLossStatus string    `json:"packet_loss_status"`  // "AVAILABLE", "UNAVAILABLE", "NOT_MEASURED"
	DurationMs       int64     `json:"duration_ms"`         // Test duration in ms
	LastChecked      time.Time `json:"last_checked"`
}
