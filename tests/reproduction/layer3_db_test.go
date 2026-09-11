package reproduction

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/stretchr/testify/require"
)

func TestLayer3_Database_FullLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "superproxy_db_layer3_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test_lifecycle.db")

	// 1. Initial open & migrations
	err = database.InitDatabase(dbPath)
	require.NoError(t, err, "Database initialization must succeed under CGO_ENABLED=0")
	require.NotNil(t, database.DB)

	// 2. Concurrent write & read test
	const workerCount = 10
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			node := models.Node{
				ID:        string(rune('A' + idx)),
				IP:        "1.2.3.4",
				Country:   "JP",
				Score:     100 + idx,
				Status:    models.StatusActive,
				LastSeen:  time.Now(),
				FirstSeen: time.Now(),
			}
			err := database.DB.Create(&node).Error
			require.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// 3. Verify count
	var count int64
	err = database.DB.Model(&models.Node{}).Count(&count).Error
	require.NoError(t, err)
	require.Equal(t, int64(workerCount), count)

	// 4. Close database connection
	sqlDB, err := database.DB.DB()
	require.NoError(t, err)
	err = sqlDB.Close()
	require.NoError(t, err)

	// 5. Reopen and verify persistence
	err = database.InitDatabase(dbPath)
	require.NoError(t, err)
	var countReopen int64
	err = database.DB.Model(&models.Node{}).Count(&countReopen).Error
	require.NoError(t, err)
	require.Equal(t, int64(workerCount), countReopen)

	// 6. Integrity check
	var integrityResult string
	err = database.DB.Raw("PRAGMA integrity_check;").Scan(&integrityResult).Error
	require.NoError(t, err)
	require.Equal(t, "ok", integrityResult)
}
