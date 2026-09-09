package models

import (
	"time"
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
	IsBlacklisted bool   `json:"is_blacklisted"`
	FraudScore    int    `json:"fraud_score"`
	ProviderName  string `json:"provider_name"`
}

type NetworkClass struct {
	ASN         string `json:"asn"`
	ISP         string `json:"isp"`
	NetworkType string `json:"network_type"` // e.g. "broadband", "hosting"
}

type PerformanceMetrics struct {
	RTT         int     `json:"rtt_ms"` // renamed from Ping
	Throughput  int64   `json:"throughput_bps"` // renamed from Speed
	PacketLoss  float64 `json:"packet_loss_pct"`
	LastChecked time.Time `json:"last_checked"`
}
