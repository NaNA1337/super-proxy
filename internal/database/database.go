package database

import (
	"errors"
	"log"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

// InitDatabase initializes the SQLite database and performs migrations
func InitDatabase(dbPath string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return err
	}

	// Auto-migrate models
	err = DB.AutoMigrate(
		&models.Node{},
		&models.PrefixIntelligence{},
		&models.PrefixObservation{},
		&models.ReputationEvidence{},
		&models.NetworkIntelligence{},
		&models.ASNObservation{},
	)
	if err != nil {
		return err
	}

	// Migrate legacy IP:port node records to stable IP identity
	if err := MigrateNodeIdentities(DB); err != nil {
		log.Printf("[Database] Warning: failed to complete node identity migration: %v", err)
	}

	log.Printf("Database initialized successfully at %s", dbPath)
	return nil
}

// MigrateNodeIdentities scans for legacy Node records where ID contains ':' (IP:port format)
// and migrates them to stable IP identity, preserving historical metrics, fail counts, and reputation.
func MigrateNodeIdentities(db *gorm.DB) error {
	if db == nil {
		return nil
	}

	var legacyNodes []models.Node
	if err := db.Where("id LIKE '%:%'").Find(&legacyNodes).Error; err != nil {
		return err
	}

	if len(legacyNodes) == 0 {
		return nil
	}

	log.Printf("[Database] Found %d legacy Node records with IP:port IDs, performing identity stabilization migration...", len(legacyNodes))

	for _, leg := range legacyNodes {
		parts := strings.Split(leg.ID, ":")
		cleanIP := parts[0]
		if cleanIP == "" {
			continue
		}

		var existing models.Node
		res := db.Where("id = ?", cleanIP).First(&existing)
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// No collision: migrate ID from IP:port to cleanIP
			legCopy := leg
			legCopy.ID = cleanIP
			if err := db.Create(&legCopy).Error; err == nil {
				_ = db.Where("id = ?", leg.ID).Delete(&models.Node{}).Error
			}
		} else if res.Error == nil {
			// Collision: merge history into existing cleanIP node, then delete legacy record
			updates := map[string]interface{}{}
			if leg.FailCount > existing.FailCount {
				updates["fail_count"] = leg.FailCount
			}
			if !leg.FirstSeen.IsZero() && (existing.FirstSeen.IsZero() || leg.FirstSeen.Before(existing.FirstSeen)) {
				updates["first_seen"] = leg.FirstSeen
			}
			if !leg.LastSeen.IsZero() && leg.LastSeen.After(existing.LastSeen) {
				updates["last_seen"] = leg.LastSeen
			}
			if leg.EndpointsJSON != "" && existing.EndpointsJSON == "" {
				updates["endpoints_json"] = leg.EndpointsJSON
			}
			if len(updates) > 0 {
				_ = db.Model(&models.Node{}).Where("id = ?", cleanIP).Updates(updates).Error
			}
			_ = db.Where("id = ?", leg.ID).Delete(&models.Node{}).Error
		}
	}

	log.Printf("[Database] Node identity stabilization migration complete.")
	return nil
}
