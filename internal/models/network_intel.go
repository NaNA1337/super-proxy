package models

import "time"

// NetworkIntelligence tracks detailed network, ASN, ISP, and hosting classifications for an IP.
type NetworkIntelligence struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP            string    `gorm:"uniqueIndex;not null" json:"ip"`
	ASN           string    `gorm:"index" json:"asn"` // e.g. "AS13335"
	ASNName       string    `json:"asn_name"`
	ISP           string    `gorm:"index" json:"isp"`
	Organization  string    `json:"organization"`
	Country       string    `json:"country"`
	CountryCode   string    `json:"country_code"`
	IsHosting     bool      `json:"is_hosting"`
	IsVPN         bool      `json:"is_vpn"`
	IsProxy       bool      `json:"is_proxy"`
	IsTor         bool      `json:"is_tor"`
	IsResidential bool      `json:"is_residential"`
	Source        string    `json:"source"`
	ObservedAt    time.Time `json:"observed_at"`
}

// ASNObservation logs individual evaluations tagged by ASN and ISP to compute multi-window risk.
type ASNObservation struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ASN          string    `gorm:"index;not null" json:"asn"` // e.g. "AS13335"
	ISP          string    `gorm:"index" json:"isp"`
	Organization string    `json:"organization"`
	IP           string    `json:"ip"`
	IsBad        bool      `json:"is_bad"`
	IsHardReject bool      `json:"is_hard_reject"`
	IsUnknown    bool      `json:"is_unknown"`
	Score        int       `json:"score"`
	ObservedAt   time.Time `gorm:"index;not null" json:"observed_at"`
}
