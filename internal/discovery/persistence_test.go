package discovery

import (
	"testing"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestUpsertFreshNodesRevivesOnlyCredentialBackedRetryableNodes(t *testing.T) {
	ClearOVPNSecretCache()
	defer ClearOVPNSecretCache()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Node{}))

	existing := []models.Node{
		{ID: "stale-fresh", IP: "198.51.100.1", Status: models.StatusStale},
		{ID: "failed-fresh", IP: "198.51.100.2", Status: models.StatusFailed, FailCount: 1},
		{ID: "dead-fresh", IP: "198.51.100.3", Status: models.StatusDead, FailCount: 3},
		{ID: "stale-missing", IP: "198.51.100.4", Status: models.StatusStale},
	}
	require.NoError(t, db.Create(&existing).Error)
	SetOVPNSecret("stale-fresh", "credential-a")
	SetOVPNSecret("failed-fresh", "credential-b")
	SetOVPNSecret("dead-fresh", "credential-c")

	fresh := []models.Node{
		{ID: "stale-fresh", IP: "198.51.100.1", Status: models.StatusDiscovered, Score: 10},
		{ID: "failed-fresh", IP: "198.51.100.2", Status: models.StatusDiscovered, Score: 20},
		{ID: "dead-fresh", IP: "198.51.100.3", Status: models.StatusDiscovered, Score: 30},
	}
	require.NoError(t, UpsertFreshNodes(db, fresh, models.NodeUpsertColumns))

	want := map[string]string{
		"stale-fresh":   models.StatusDiscovered,
		"failed-fresh":  models.StatusDiscovered,
		"dead-fresh":    models.StatusDead,
		"stale-missing": models.StatusStale,
	}
	for id, status := range want {
		var node models.Node
		require.NoError(t, db.First(&node, "id = ?", id).Error)
		require.Equal(t, status, node.Status, id)
	}
}

func TestUpsertVettedNodesRevivesCleanDeadNodeWithFreshCredentials(t *testing.T) {
	ClearOVPNSecretCache()
	defer ClearOVPNSecretCache()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Node{}))
	require.NoError(t, db.Create(&models.Node{ID: "kr-node", IP: "198.51.100.9", Country: "KR", Status: models.StatusDead, FailCount: 3}).Error)
	SetOVPNSecret("kr-node", "fresh-credential")
	fresh := []models.Node{{
		ID: "kr-node", IP: "198.51.100.9", Country: "KR", Status: models.StatusReputationChecked,
		Score: 70, NetClass: models.NetworkClass{ASN: "AS64500", NetworkType: "residential"},
	}}
	require.NoError(t, UpsertVettedNodes(db, fresh, models.NodeUpsertColumns))
	var node models.Node
	require.NoError(t, db.First(&node, "id = ?", "kr-node").Error)
	require.Equal(t, models.StatusReputationChecked, node.Status)
	require.Zero(t, node.FailCount)
	require.Equal(t, "AS64500", node.NetClass.ASN)
}
