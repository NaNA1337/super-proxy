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

// Node represents a VPN Gate node
type Node struct {
	ID        string    `gorm:"primaryKey" json:"id"`
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
	RTT           int       `json:"rtt_ms"`          // Round-trip time in milliseconds
	Throughput    int64     `json:"throughput_bps"`  // Aggregate throughput in bps
	DownloadSpeed int64     `json:"download_bps"`    // Download throughput
	UploadSpeed   int64     `json:"upload_bps"`      // Upload throughput
	UploadStatus  string    `json:"upload_status"`   // "AVAILABLE", "UNAVAILABLE", "FAILED"
	PacketLoss    float64   `json:"packet_loss_pct"` // Packet loss percentage
	DurationMs    int64     `json:"duration_ms"`     // Test duration in ms
	LastChecked   time.Time `json:"last_checked"`
}
