package models

import "time"

// PrefixIntelligence tracks aggregate CIDR reputation metrics.
type PrefixIntelligence struct {
	Prefix          string    `gorm:"primaryKey" json:"prefix"` // e.g. "198.51.100.0/24"
	SampleCount     int       `json:"sample_count"`
	BadCount        int       `json:"bad_count"`
	HardRejectCount int       `json:"hard_reject_count"`
	AverageScore    float64   `json:"average_score"`
	LastSeen        time.Time `json:"last_seen"`
}
