package discovery

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	err = db.AutoMigrate(&models.Node{})
	if err != nil {
		t.Fatalf("failed to migrate models: %v", err)
	}
	return db
}

func TestDiscovery_PeriodicUpsertAndEndpointUpdate(t *testing.T) {
	db := setupTestDB(t)

	ip := "198.51.100.50"
	firstSeen := time.Now().Add(-2 * time.Hour)

	// 1. First discovery run
	ep1 := []models.OpenVPNEndpoint{{Host: ip, Port: 1194, Proto: "udp"}}
	ep1JSON, _ := json.Marshal(ep1)

	node1 := models.Node{
		ID:            ip,
		HostName:      "vpn-node-1",
		IP:            ip,
		Score:         100,
		Country:       "JP",
		CountryL:      "Japan",
		Sessions:      10,
		Uptime:        60000,
		Users:         5,
		TotalTraffic:  1000000,
		LogType:       "2weeks",
		Operator:      "Vol1",
		Message:       "Initial message",
		OpenVPN:       "dGVzdDE=",
		OpenVPNConfig: "dev tun\nproto udp\nremote 198.51.100.50 1194\n",
		EndpointsJSON: string(ep1JSON),
		EndpointHost:  ip,
		EndpointPort:  1194,
		EndpointProto: "udp",
		Status:        models.StatusDiscovered,
		FirstSeen:     firstSeen,
		LastSeen:      firstSeen,
		FailCount:     2,
	}

	res := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(models.NodeUpsertColumns),
	}).Create(&node1)
	if res.Error != nil {
		t.Fatalf("failed to create node1: %v", res.Error)
	}

	// 2. Second discovery run: endpoint port changed to 8443, traffic increased, score updated
	ep2 := []models.OpenVPNEndpoint{
		{Host: ip, Port: 8443, Proto: "tcp"},
		{Host: "backup.example.com", Port: 443, Proto: "tcp"},
	}
	ep2JSON, _ := json.Marshal(ep2)
	now := time.Now()

	node2 := models.Node{
		ID:            ip, // Must be identical stable ID!
		HostName:      "vpn-node-1-updated",
		IP:            ip,
		Score:         250,
		Country:       "JP",
		CountryL:      "Japan",
		Sessions:      20,
		Uptime:        120000,
		Users:         15,
		TotalTraffic:  5000000,
		LogType:       "2weeks",
		Operator:      "Vol1-Updated",
		Message:       "Updated message",
		OpenVPN:       "dGVzdDI=",
		OpenVPNConfig: "dev tun\nproto tcp\nremote 198.51.100.50 8443\n",
		EndpointsJSON: string(ep2JSON),
		EndpointHost:  ip,
		EndpointPort:  8443,
		EndpointProto: "tcp",
		Status:        models.StatusDiscovered,
		FirstSeen:     now, // should not overwrite existing firstSeen
		LastSeen:      now,
		FailCount:     0, // should not overwrite fail_count
	}

	res = db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(models.NodeUpsertColumns),
	}).Create(&node2)
	if res.Error != nil {
		t.Fatalf("failed to update node2: %v", res.Error)
	}

	// 3. Verify DB record has 2nd discovery data without old endpoint residual
	var fetched models.Node
	if err := db.Where("id = ?", ip).First(&fetched).Error; err != nil {
		t.Fatalf("failed to query node: %v", err)
	}

	// Identity must remain stable
	if fetched.ID != ip {
		t.Errorf("Node ID mismatch: expected %s, got %s", ip, fetched.ID)
	}
	// Updated endpoint fields
	if fetched.EndpointPort != 8443 {
		t.Errorf("EndpointPort not updated: expected 8443, got %d", fetched.EndpointPort)
	}
	if fetched.EndpointProto != "tcp" {
		t.Errorf("EndpointProto not updated: expected tcp, got %s", fetched.EndpointProto)
	}
	if fetched.TotalTraffic != 5000000 {
		t.Errorf("TotalTraffic not updated: expected 5000000, got %d", fetched.TotalTraffic)
	}
	if fetched.Score != 250 {
		t.Errorf("Score not updated: expected 250, got %d", fetched.Score)
	}
	if fetched.EndpointsJSON != string(ep2JSON) {
		t.Errorf("EndpointsJSON not updated")
	}
	// Historical data preservation
	if fetched.FailCount != 2 {
		t.Errorf("FailCount was overwritten! Expected 2, got %d", fetched.FailCount)
	}
}

func TestDatabase_LegacyNodeIdentityMigration(t *testing.T) {
	db := setupTestDB(t)

	legacyID := "198.51.100.88:1194"
	cleanIP := "198.51.100.88"
	firstSeen := time.Now().Add(-24 * time.Hour)

	legacyNode := models.Node{
		ID:           legacyID,
		IP:           cleanIP,
		Score:        120,
		Country:      "JP",
		EndpointHost: cleanIP,
		EndpointPort: 1194,
		FailCount:    7,
		FirstSeen:    firstSeen,
		Status:       models.StatusQualified,
	}

	if err := db.Create(&legacyNode).Error; err != nil {
		t.Fatalf("failed to create legacy node: %v", err)
	}

	// Run migration
	if err := database.MigrateNodeIdentities(db); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	// Legacy record must be deleted
	var legacy models.Node
	if err := db.Where("id = ?", legacyID).First(&legacy).Error; err == nil {
		t.Errorf("expected legacy record %s to be deleted, but still found", legacyID)
	}

	// Stable IP record must exist with preserved history
	var migrated models.Node
	if err := db.Where("id = ?", cleanIP).First(&migrated).Error; err != nil {
		t.Fatalf("migrated record %s not found: %v", cleanIP, err)
	}
	if migrated.ID != cleanIP {
		t.Errorf("expected migrated ID to be %s, got %s", cleanIP, migrated.ID)
	}
	if migrated.FailCount != 7 {
		t.Errorf("history lost: expected FailCount 7, got %d", migrated.FailCount)
	}
	if migrated.Status != models.StatusQualified {
		t.Errorf("status lost: expected QUALIFIED, got %s", migrated.Status)
	}
}
