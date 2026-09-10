package models

import "time"

// ReputationEvidence stores raw evidence from individual reputation providers
// to retain full auditability into why an IP was classified as GOOD, BAD, or UNKNOWN.
type ReputationEvidence struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP              string    `gorm:"index;not null" json:"ip"`
	Provider        string    `gorm:"index;not null" json:"provider"` // AbuseIPDB, GreyNoise, IPQS, IPInfo
	Status          string    `json:"status"`                         // GOOD, BAD, UNKNOWN
	Score           float64   `json:"score"`
	AbuseConfidence int       `json:"abuse_confidence"`
	FraudScore      int       `json:"fraud_score"`
	IsVPN           bool      `json:"is_vpn"`
	IsProxy         bool      `json:"is_proxy"`
	IsTor           bool      `json:"is_tor"`
	IsHosting       bool      `json:"is_hosting"`
	IsResidential   bool      `json:"is_residential"`
	ASN             string    `json:"asn"`
	ISP             string    `json:"isp"`
	Organization    string    `json:"organization"`
	Country         string    `json:"country"`
	CountryCode     string    `json:"country_code"`
	Reports         int       `json:"reports"`
	RawCategory     string    `json:"raw_category"`
	ObservedAt      time.Time `gorm:"index" json:"observed_at"`
	Error           string    `json:"error,omitempty"`
}
