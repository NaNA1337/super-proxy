package agentapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/stretchr/testify/require"
)

func TestQualifiedPoolHidesNodesWithoutRuntimeCredentials(t *testing.T) {
	require.NoError(t, database.InitDatabase(":memory:"))
	discovery.ClearOVPNSecretCache()
	defer discovery.ClearOVPNSecretCache()
	require.NoError(t, database.DB.Create(&[]models.Node{
		{ID: "available", IP: "198.51.100.1", Status: models.StatusDiscovered},
		{ID: "missing", IP: "198.51.100.2", Status: models.StatusDiscovered},
	}).Error)
	discovery.SetOVPNSecret("available", "credential")

	rr := httptest.NewRecorder()
	handlePoolQualified(rr, httptest.NewRequest(http.MethodGet, "/api/v1/pool/qualified", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	var nodes []models.Node
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &nodes))
	require.Len(t, nodes, 1)
	require.Equal(t, "available", nodes[0].ID)
	require.True(t, nodes[0].CredentialsAvailable)
}

func TestManualSwitchRejectsMissingCredentialsSynchronously(t *testing.T) {
	require.NoError(t, database.InitDatabase(":memory:"))
	discovery.ClearOVPNSecretCache()
	defer discovery.ClearOVPNSecretCache()
	require.NoError(t, database.DB.Create(&models.Node{
		ID: "missing", IP: "198.51.100.2", Status: models.StatusDiscovered,
	}).Error)
	SetScheduler(scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"}))

	body := bytes.NewBufferString(`{"node_id":"missing"}`)
	rr := httptest.NewRecorder()
	handleSlotAction(rr, httptest.NewRequest(http.MethodPost, "/api/v1/slots/0/switch", body))
	require.Equal(t, http.StatusConflict, rr.Code)
	require.True(t, strings.Contains(rr.Body.String(), "waiting for VPN Gate rediscovery"), rr.Body.String())
}
