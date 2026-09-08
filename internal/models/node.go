package models

import (
	"time"
)

// Node represents a VPN Gate node
type Node struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	HostName  string    `json:"hostname"`
	IP        string    `gorm:"index" json:"ip"`
	Score     int       `json:"score"`
	Ping      int       `json:"ping"`
	Speed     int64     `json:"speed"` // in bytes per second
	Country   string    `gorm:"index" json:"country"`
	CountryL  string    `json:"country_long"`
	Sessions  int       `json:"sessions"`
	Uptime    int64     `json:"uptime"` // in milliseconds
	Users     int       `json:"users"`
	Message   string    `json:"message"`
	OpenVPN   string    `json:"openvpn_config_base64"`
	
	// Internal tracking fields
	Status       string    `gorm:"index" json:"status"` // NEW, DISCOVERED, ACTIVE, FAILED, COOLDOWN, DEAD
	LastSeen     time.Time `json:"last_seen"`
	FirstSeen    time.Time `json:"first_seen"`
	FailCount    int       `json:"fail_count"`
	HealthScore  int       `json:"health_score"`
}
