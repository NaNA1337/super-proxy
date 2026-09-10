package models

import "time"

// PrefixIntelligence tracks rich aggregate CIDR reputation metrics for a subnet.
type PrefixIntelligence struct {
	Prefix            string    `gorm:"primaryKey" json:"prefix"` // e.g. "198.51.100.0/24"
	PrefixLength      int       `json:"prefix_length"`            // e.g. 24
	SampleCount       int       `json:"sample_count"`
	BadCount          int       `json:"bad_count"`
	UnknownCount      int       `json:"unknown_count"`
	HardRejectCount   int       `json:"hard_reject_count"`
	BadRatio          float64   `json:"bad_ratio"`
	HardRejectRatio   float64   `json:"hard_reject_ratio"`
	UnknownRatio      float64   `json:"unknown_ratio"`
	AverageScore      float64   `json:"average_score"`
	VPNCount          int       `json:"vpn_count"`
	ProxyCount        int       `json:"proxy_count"`
	TorCount          int       `json:"tor_count"`
	HostingCount      int       `json:"hosting_count"`
	ResidentialCount  int       `json:"residential_count"`
	DistinctIPs       int       `json:"distinct_ips"`
	ASNDiversity      int       `json:"asn_diversity"`
	ISPDiversity      int       `json:"isp_diversity"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
}

// PrefixObservation records individual observations within a CIDR prefix to enable
// accurate time-windowed aggregations (24h, 7d, 30d, 90d).
type PrefixObservation struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Prefix       string    `gorm:"index;not null" json:"prefix"` // e.g. "198.51.100.0/24"
	IP           string    `gorm:"index;not null" json:"ip"`
	Score        int       `json:"score"`
	Status       string    `json:"status"` // GOOD, BAD, UNKNOWN
	IsBad        bool      `json:"is_bad"`
	IsHardReject bool      `json:"is_hard_reject"`
	IsUnknown    bool      `json:"is_unknown"`
	ASN          string    `json:"asn"`
	ISP          string    `json:"isp"`
	NetworkType  string    `json:"network_type"` // e.g. "hosting", "residential"
	IsVPN        bool      `json:"is_vpn"`
	IsProxy      bool      `json:"is_proxy"`
	IsTor        bool      `json:"is_tor"`
	IsHosting    bool      `json:"is_hosting"`
	ObservedAt   time.Time `gorm:"index;not null" json:"observed_at"`
}
