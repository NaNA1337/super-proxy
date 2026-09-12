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

// NodeUpsertColumns defines the single source of truth for fields refreshed during discovery.
// Note: openvpn_config_base64 is intentionally excluded as raw secrets are never persisted.
var NodeUpsertColumns = []string{
	"score",
	"country",
	"country_long",
	"host_name",
	"sessions",
	"uptime",
	"users",
	"message",
	"openvpn_config",
	"endpoints_json",
	"endpoint_host",
	"endpoint_port",
	"endpoint_proto",
	"total_traffic",
	"log_type",
	"operator",
	"last_seen",
}

// Node represents a VPN Gate node with stable identity.
type Node struct {
	ObservedExitIP string `gorm:"column:observed_exit_ip" json:"observed_exit_ip,omitempty"` // Measured NAT egress; not the VPN server endpoint.
	ID             string `gorm:"primaryKey;column:id" json:"id"`                            // Stable node identity (IP)
	// CredentialsAvailable is runtime-only. Raw OpenVPN credentials never enter the DB or API.
	CredentialsAvailable bool   `gorm:"-" json:"credentials_available"`
	HostName             string `gorm:"column:host_name" json:"hostname"`
	IP                   string `gorm:"index;column:ip" json:"ip"`
	Score                int    `gorm:"column:score" json:"score"` // Internally calculated admission/performance score
	Country              string `gorm:"index;column:country" json:"country"`
	CountryL             string `gorm:"column:country_long" json:"country_long"`
	Sessions             int    `gorm:"column:sessions" json:"sessions"`
	Uptime               int64  `gorm:"column:uptime" json:"uptime"` // in milliseconds
	Users                int    `gorm:"column:users" json:"users"`
	Message              string `gorm:"column:message" json:"message"`
	// OpenVPN holds raw base64 credentials in-memory ONLY during discovery.
	// It is NEVER persisted to DB (column is kept empty) and NEVER exposed in JSON.
	OpenVPN   string `gorm:"column:openvpn_config_base64" json:"-"`
	SecretRef string `gorm:"column:secret_ref" json:"secret_ref,omitempty"`

	// VPN Gate Discovery metadata
	TotalTraffic int64  `gorm:"column:total_traffic" json:"total_traffic"`
	LogType      string `gorm:"column:log_type" json:"log_type"`
	Operator     string `gorm:"column:operator" json:"operator"`

	// Structured OpenVPN endpoint information (separated from Node identity)
	EndpointHost  string `gorm:"index;column:endpoint_host" json:"endpoint_host"`
	EndpointPort  int    `gorm:"index;column:endpoint_port" json:"endpoint_port"`
	EndpointProto string `gorm:"column:endpoint_proto" json:"endpoint_proto"`
	OpenVPNConfig string `gorm:"column:openvpn_config" json:"openvpn_config,omitempty"` // Canonical safe local .ovpn config (credentials stripped)
	EndpointsJSON string `gorm:"column:endpoints_json" json:"endpoints_json"`           // JSON-encoded []OpenVPNEndpoint

	Status        string    `gorm:"index;column:status" json:"status"` // NEW, DISCOVERED, ACTIVE, FAILED, COOLDOWN, DEAD
	LastSeen      time.Time `gorm:"column:last_seen" json:"last_seen"`
	FirstSeen     time.Time `gorm:"column:first_seen" json:"first_seen"`
	FailCount     int       `gorm:"column:fail_count" json:"fail_count"`
	LastError     string    `gorm:"column:last_error" json:"last_error,omitempty"`
	LastFailureAt time.Time `gorm:"column:last_failure_at" json:"last_failure_at,omitempty"`

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

// Metric status values
const (
	MetricStatusAvailable   = "AVAILABLE"
	MetricStatusUnavailable = "UNAVAILABLE"
	MetricStatusNotMeasured = "NOT_MEASURED"
	MetricStatusError       = "ERROR"
)

type PerformanceMetrics struct {
	RTT              int       `json:"rtt_ms"`             // Round-trip time in milliseconds (-1 if unmeasured)
	Throughput       int64     `json:"throughput_bps"`     // Aggregate throughput in bps
	DownloadSpeed    int64     `json:"download_bps"`       // Download throughput
	UploadSpeed      int64     `json:"upload_bps"`         // Upload throughput
	UploadStatus     string    `json:"upload_status"`      // AVAILABLE, UNAVAILABLE, NOT_MEASURED, ERROR
	SpeedStatus      string    `json:"speed_status"`       // AVAILABLE, UNAVAILABLE, NOT_MEASURED, ERROR
	PacketLoss       float64   `json:"packet_loss_pct"`    // Packet loss percentage (-1 if unmeasured)
	PacketLossStatus string    `json:"packet_loss_status"` // AVAILABLE, UNAVAILABLE, NOT_MEASURED, ERROR
	DurationMs       int64     `json:"duration_ms"`        // Test duration in ms
	LastChecked      time.Time `json:"last_checked"`
}
