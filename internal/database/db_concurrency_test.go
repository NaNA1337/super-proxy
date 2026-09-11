package database

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestDatabase_ConcurrentReadWriteStress simulates intense concurrent access from
// Discovery, Scheduler, API, Health, and Reputation without "database is locked" errors.
func TestDatabase_ConcurrentReadWriteStress(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_stress.db")

	require.NoError(t, InitDatabase(dbPath))

	var journalMode string
	DB.Raw("PRAGMA journal_mode;").Scan(&journalMode)
	require.Equal(t, "wal", journalMode)

	const workerCount = 10
	const iterationsPerWorker = 30
	var wg sync.WaitGroup

	// Pre-populate some nodes
	for i := 0; i < 5; i++ {
		node := &models.Node{
			ID:      fmt.Sprintf("node-base-%d", i),
			IP:      fmt.Sprintf("198.51.100.%d", i+1),
			Status:  models.StatusDiscovered,
			Score:   100,
			Country: "JP",
		}
		require.NoError(t, DB.Create(node).Error)
	}

	errChan := make(chan error, workerCount*iterationsPerWorker)

	// Launch concurrent writers and readers
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		workerID := w
		go func() {
			defer wg.Done()
			for iter := 0; iter < iterationsPerWorker; iter++ {
				if workerID%2 == 0 {
					// Writer: Create or Update in transaction
					err := DB.Transaction(func(tx *gorm.DB) error {
						n := &models.Node{
							ID:      fmt.Sprintf("node-%d-%d", workerID, iter),
							IP:      fmt.Sprintf("203.0.113.%d", (workerID*10+iter)%250+1),
							Status:  models.StatusDiscovered,
							Score:   workerID*10 + iter,
							Country: "JP",
						}
						if err := tx.Save(n).Error; err != nil {
							return err
						}
						return tx.Model(n).Update("score", n.Score+5).Error
					})
					if err != nil {
						errChan <- fmt.Errorf("writer %d-%d error: %w", workerID, iter, err)
					}
				} else {
					// Reader: Query nodes
					var count int64
					if err := DB.Model(&models.Node{}).Count(&count).Error; err != nil {
						errChan <- fmt.Errorf("reader %d-%d count error: %w", workerID, iter, err)
					}
					var nodes []models.Node
					if err := DB.Where("status = ?", models.StatusDiscovered).Limit(10).Find(&nodes).Error; err != nil {
						errChan <- fmt.Errorf("reader %d-%d find error: %w", workerID, iter, err)
					}
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}

	// Verify integrity check passes after high concurrency
	var integrity string
	DB.Raw("PRAGMA integrity_check;").Scan(&integrity)
	require.Equal(t, "ok", integrity)
}
