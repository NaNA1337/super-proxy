package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestCleanDatabaseBacksUpLegacyDataAndCreatesFreshSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "manager.db")
	require.NoError(t, InitDatabase(dbPath))
	require.NoError(t, DB.Create(&models.Node{
		ID:        "198.51.100.10",
		IP:        "198.51.100.10",
		Country:   "JP",
		Status:    models.StatusFailed,
		FailCount: 3,
	}).Error)
	oldSQL, err := DB.DB()
	require.NoError(t, err)
	require.NoError(t, oldSQL.Close())
	DB = nil

	cleanedAt := time.Date(2026, 9, 12, 10, 30, 0, 123, time.UTC)
	backupPath, err := cleanDatabaseAt(dbPath, cleanedAt)
	require.NoError(t, err)
	require.Equal(t, dbPath+".backup-20260912T103000.000000123Z", backupPath)

	backupDB, err := gorm.Open(sqlite.Open(backupPath), &gorm.Config{})
	require.NoError(t, err)
	var oldCount int64
	require.NoError(t, backupDB.Model(&models.Node{}).Count(&oldCount).Error)
	require.EqualValues(t, 1, oldCount)
	backupSQL, err := backupDB.DB()
	require.NoError(t, err)
	require.NoError(t, backupSQL.Close())

	freshDB, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	var freshCount int64
	require.NoError(t, freshDB.Model(&models.Node{}).Count(&freshCount).Error)
	require.Zero(t, freshCount)
	freshSQL, err := freshDB.DB()
	require.NoError(t, err)
	require.NoError(t, freshSQL.Close())

	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestCleanDatabaseRejectsRelativePath(t *testing.T) {
	_, err := cleanDatabaseAt("manager.db", time.Now())
	require.ErrorContains(t, err, "must be absolute")
}
