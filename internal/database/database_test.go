package database

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestParseLegacyNodeID(t *testing.T) {
	tests := []struct {
		name         string
		inputID      string
		expectedIP   string
		expectedLeg  bool
	}{
		{
			name:        "Pure IPv4",
			inputID:     "192.168.1.1",
			expectedIP:  "192.168.1.1",
			expectedLeg: false,
		},
		{
			name:        "Legacy IPv4 with port",
			inputID:     "1.2.3.4:443",
			expectedIP:  "1.2.3.4",
			expectedLeg: true,
		},
		{
			name:        "Bare IPv6",
			inputID:     "2001:db8::1",
			expectedIP:  "2001:db8::1",
			expectedLeg: false,
		},
		{
			name:        "Bracketed IPv6 with port",
			inputID:     "[2001:db8::1]:443",
			expectedIP:  "2001:db8::1",
			expectedLeg: true,
		},
		{
			name:        "Bare IPv6 with multiple colons (not legacy)",
			inputID:     "2001:db8::1:443",
			expectedIP:  "2001:db8::1:443",
			expectedLeg: false,
		},
		{
			name:        "Malformed: multiple colons invalid",
			inputID:     "invalid:port:extra:colons",
			expectedIP:  "",
			expectedLeg: false,
		},
		{
			name:        "Malformed: empty string",
			inputID:     "",
			expectedIP:  "",
			expectedLeg: false,
		},
		{
			name:        "Invalid port number out of range",
			inputID:     "1.2.3.4:99999",
			expectedIP:  "",
			expectedLeg: false,
		},
		{
			name:        "Non-numeric port",
			inputID:     "1.2.3.4:abc",
			expectedIP:  "",
			expectedLeg: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cleanIP, isLegacy := ParseLegacyNodeID(tc.inputID)
			assert.Equal(t, tc.expectedIP, cleanIP)
			assert.Equal(t, tc.expectedLeg, isLegacy)
		})
	}
}

func TestMigrateNodeIdentities_PreservesHistory(t *testing.T) {
	tempDB := filepath.Join(t.TempDir(), "migration_test.db")
	db, err := gorm.Open(sqlite.Open(tempDB), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.Node{})
	require.NoError(t, err)

	t1 := time.Now().Add(-48 * time.Hour)
	t2 := time.Now().Add(-1 * time.Hour)

	// Insert legacy node
	legacyNode := models.Node{
		ID:            "10.0.0.1:1194",
		Country:       "JP",
		Score:         85,
		FailCount:     3,
		FirstSeen:     t1,
		LastSeen:      t2,
		EndpointsJSON: `[{"ip":"10.0.0.1","port":1194}]`,
	}
	require.NoError(t, db.Create(&legacyNode).Error)

	// Insert bare IPv6 node that must NOT be touched or corrupted
	bareIPv6 := models.Node{
		ID:        "2001:db8::1",
		Country:   "US",
		Score:     90,
		FirstSeen: t1,
		LastSeen:  t2,
	}
	require.NoError(t, db.Create(&bareIPv6).Error)

	// Insert unbracketed ambiguous node that must be skipped without guessing
	ambiguous := models.Node{
		ID:        "2001:db8::1:1194",
		Country:   "DE",
		Score:     70,
		FirstSeen: t1,
		LastSeen:  t2,
	}
	require.NoError(t, db.Create(&ambiguous).Error)

	// Run migration
	err = MigrateNodeIdentities(db)
	require.NoError(t, err)

	// Check legacy node migrated to "10.0.0.1"
	var migrated models.Node
	err = db.Where("id = ?", "10.0.0.1").First(&migrated).Error
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", migrated.ID)
	assert.Equal(t, 3, migrated.FailCount)
	assert.Equal(t, "JP", migrated.Country)
	assert.True(t, migrated.FirstSeen.Equal(t1) || migrated.FirstSeen.Sub(t1).Abs() < time.Second)

	// Check old legacy ID was cleaned up
	var oldRecord models.Node
	err = db.Where("id = ?", "10.0.0.1:1194").First(&oldRecord).Error
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

	// Check bare IPv6 was untouched
	var v6Record models.Node
	err = db.Where("id = ?", "2001:db8::1").First(&v6Record).Error
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", v6Record.ID)

	// Check ambiguous node was preserved intact without guessing
	var ambRecord models.Node
	err = db.Where("id = ?", "2001:db8::1:1194").First(&ambRecord).Error
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1:1194", ambRecord.ID)
}
