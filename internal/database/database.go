package database

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/glebarez/sqlite"
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

	sqlDB, err := DB.DB()
	if err == nil {
		// SQLite pragmas such as foreign_keys and busy_timeout are scoped to a
		// connection. Keep a single shared connection so every operation uses
		// the configured safety policy and in-memory databases remain coherent.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
	}

	// Explicitly configure SQLite pragmas for high concurrency and fail-safe operation
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA synchronous=NORMAL;",
	} {
		if err := DB.Exec(pragma).Error; err != nil {
			return fmt.Errorf("configure SQLite (%s): %w", pragma, err)
		}
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

	// Strip any legacy raw OpenVPN secrets from database
	if err := MigrateStripRawOVPN(DB); err != nil {
		log.Printf("[Database] Warning: failed to strip legacy raw OpenVPN secrets: %v", err)
	}

	log.Printf("Database initialized successfully at %s", dbPath)
	return nil
}

// ParseLegacyNodeID safely inspects a Node ID to determine if it represents a legacy IP:port record.
// Strictly supports:
//   - IPv4 ("1.2.3.4") -> ("1.2.3.4", false)
//   - IPv4:port ("1.2.3.4:443") -> ("1.2.3.4", true)
//   - Bare IPv6 ("2001:db8::1") -> ("2001:db8::1", false)
//   - Bracketed IPv6:port ("[2001:db8::1]:443") -> ("2001:db8::1", true)
//   - Ambiguous / Malformed IDs (e.g. unbracketed multiple colons "2001:db8::1:443" or "invalid:port:extra")
//     -> ("", false) with a warning log, NEVER guessing or corrupting addresses.
func ParseLegacyNodeID(id string) (string, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false
	}

	// 1. If it's already a valid IPv4 or IPv6 address, it is NOT legacy
	if ip := net.ParseIP(id); ip != nil {
		return ip.String(), false
	}

	// 2. Try strict net.SplitHostPort
	host, portStr, err := net.SplitHostPort(id)
	if err == nil {
		port, portErr := strconv.Atoi(portStr)
		if portErr == nil && port > 0 && port <= 65535 {
			if ip := net.ParseIP(host); ip != nil {
				return ip.String(), true
			}
		}
	}

	// 3. If net.SplitHostPort failed (e.g. unbracketed IPv6 with port, or malformed):
	// Do NOT guess! Skip with warning.
	return "", false
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

	log.Printf("[Database] Found %d candidate legacy Node records with colons in ID, performing identity stabilization migration...", len(legacyNodes))

	for _, leg := range legacyNodes {
		cleanIP, isLegacy := ParseLegacyNodeID(leg.ID)
		if !isLegacy || cleanIP == "" {
			log.Printf("[Database] Skipping non-legacy or ambiguous Node ID %q during identity migration (preserving historical ID intact)", leg.ID)
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

// MigrateStripRawOVPN scans for any legacy Node records where openvpn_config_base64 is populated
// and strips the raw secrets, setting openvpn_config_base64 to an empty string.
// This migration is idempotent, transactional, crash-safe, and preserves all node identities,
// historical metrics, and reputations.
func MigrateStripRawOVPN(db *gorm.DB) error {
	if db == nil {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec("UPDATE nodes SET openvpn_config_base64 = '' WHERE openvpn_config_base64 IS NOT NULL AND openvpn_config_base64 != ''")
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected > 0 {
			log.Printf("[Database] Stripped raw OpenVPN secrets from %d legacy Node record(s).", res.RowsAffected)
		}
		return nil
	})
}
