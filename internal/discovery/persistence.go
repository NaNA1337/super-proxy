package discovery

import (
	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UpsertFreshNodes persists public discovery metadata and revives only nodes
// whose credentials were refreshed into the runtime cache by this discovery run.
func UpsertFreshNodes(db *gorm.DB, nodes []models.Node, upsertCols []string) error {
	if db == nil || len(nodes) == 0 {
		return nil
	}
	ids := make([]string, 0, len(nodes))
	for i := range nodes {
		if _, ok := GetOVPNSecret(nodes[i].ID); ok {
			ids = append(ids, nodes[i].ID)
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(upsertCols),
		}).Create(&nodes).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		return tx.Model(&models.Node{}).
			Where("id IN ? AND status IN ? AND fail_count < 3", ids, []string{
				models.StatusStale,
				models.StatusFailed,
				models.StatusCooldown,
			}).
			Update("status", models.StatusDiscovered).Error
	})
}
