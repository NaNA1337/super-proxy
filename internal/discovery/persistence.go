package discovery

import (
	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UpsertFreshNodes persists public discovery metadata and revives nodes whose
// credentials were refreshed into the runtime cache by this discovery run.
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
			Where("id IN ? AND status IN ?", ids, []string{
				models.StatusStale,
				models.StatusFailed,
				models.StatusCooldown,
				models.StatusDead,
			}).
			Update("status", models.StatusDiscovered).Error
	})
}

// UpsertVettedNodes persists a complete discovery batch after pre-admission.
// Existing live tunnels keep their runtime state; retryable inactive nodes are
// advanced to REPUTATION_CHECKED only when this refresh passed all checks.
func UpsertVettedNodes(db *gorm.DB, nodes []models.Node, upsertCols []string) error {
	if db == nil || len(nodes) == 0 {
		return nil
	}
	acceptedIDs := make([]string, 0, len(nodes))
	rejectedIDs := make([]string, 0, len(nodes))
	for i := range nodes {
		if nodes[i].Status == models.StatusReputationChecked {
			if _, ok := GetOVPNSecret(nodes[i].ID); ok {
				acceptedIDs = append(acceptedIDs, nodes[i].ID)
			}
		} else {
			rejectedIDs = append(rejectedIDs, nodes[i].ID)
			DeleteOVPNSecret(nodes[i].ID)
		}
	}

	columns := append([]string{}, upsertCols...)
	columns = append(columns,
		"rep_status", "rep_is_blacklisted", "rep_fraud_score", "rep_provider_name", "rep_details",
		"net_asn", "net_isp", "net_organization", "net_network_type",
		"net_is_vpn", "net_is_proxy", "net_is_tor", "net_is_hosting",
		"last_error", "last_failure_at",
	)
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(columns),
		}).Create(&nodes).Error; err != nil {
			return err
		}
		if len(acceptedIDs) > 0 {
			if err := tx.Model(&models.Node{}).
				Where("id IN ? AND status IN ?", acceptedIDs, []string{
					models.StatusNew, models.StatusDiscovered, models.StatusReputationChecked,
					models.StatusStale, models.StatusFailed, models.StatusCooldown, models.StatusDead,
				}).Updates(map[string]interface{}{
				"status": models.StatusReputationChecked, "last_error": "", "last_failure_at": nil,
			}).Error; err != nil {
				return err
			}
		}
		if len(rejectedIDs) > 0 {
			return tx.Model(&models.Node{}).
				Where("id IN ? AND status IN ?", rejectedIDs, []string{
					models.StatusNew, models.StatusDiscovered, models.StatusReputationChecked,
					models.StatusHealthy, models.StatusQualified, models.StatusStale,
					models.StatusFailed, models.StatusCooldown,
				}).Update("status", models.StatusFailed).Error
		}
		return nil
	})
}
