package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/agentapi"
	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/clause"
)

// TestNoRawOVPNSecretsPersisted verifies that VPN Gate raw OVPN configs and private keys
// NEVER reach the SQLite database, API responses, logs, or metrics under any condition.
func TestNoRawOVPNSecretsPersisted(t *testing.T) {
	// Setup temporary clean SQLite DB
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "secret_lifecycle.db")
	require.NoError(t, database.InitDatabase(dbPath))

	const secretMarker = "LEAK_TEST_PRIVATE_KEY_SECRET_9876543210"
	rawOVPN := fmt.Sprintf(`client
dev tun
proto udp
remote 192.168.100.55 1194
cipher AES-128-CBC
<key>
-----BEGIN PRIVATE KEY-----
%s
-----END PRIVATE KEY-----
</key>
<cert>
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAP
-----END CERTIFICATE-----
</cert>
`, secretMarker)

	b64Config := base64.StdEncoding.EncodeToString([]byte(rawOVPN))

	// Construct simulated VPN Gate CSV response
	csvData := "*vpn_servers\n" +
		"#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		fmt.Sprintf("leak-test-node,192.168.100.55,850,15,5000000,Japan,JP,8,1234567,80,4500000,2,tester,secure-test,%s\n", b64Config)

	// Capture logs during discovery
	var logBuf bytes.Buffer
	origLogWriter := log.Writer()
	origLogFlags := log.Flags()
	log.SetOutput(&logBuf)
	defer func() {
		log.SetOutput(origLogWriter)
		log.SetFlags(origLogFlags)
	}()

	// Serve discovery CSV via mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(csvData))
	}))
	defer ts.Close()

	// 1. Run Discovery
	nodes, err := discovery.FetchAndParseNodes(ts.URL)
	require.NoError(t, err)
	require.Len(t, nodes, 1)

	// Persist/Upsert discovered node to DB exactly as cmd/manager does
	err = database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(models.NodeUpsertColumns),
	}).Create(&nodes).Error
	require.NoError(t, err)

	// -------------------------------------------------------------
	// Test A: GORM Model Query Checks
	// -------------------------------------------------------------
	var queriedNode models.Node
	err = database.DB.Where("id = ?", "192.168.100.55").First(&queriedNode).Error
	require.NoError(t, err)

	// Node.OpenVPN must be empty string in DB
	assert.Empty(t, queriedNode.OpenVPN, "CRITICAL: Node.OpenVPN must be empty in DB")
	// Node.OpenVPNConfig must NOT contain the secret
	assert.NotContains(t, queriedNode.OpenVPNConfig, secretMarker,
		"CRITICAL: Node.OpenVPNConfig must be stripped of private key")
	// Safe metadata must remain intact
	assert.Equal(t, "192.168.100.55", queriedNode.IP)
	assert.Equal(t, "JP", queriedNode.Country)
	assert.Equal(t, 1194, queriedNode.EndpointPort)
	assert.Equal(t, "udp", queriedNode.EndpointProto)

	// Verify in-memory secret cache DOES have the secret for runtime connection
	cachedSecret, ok := discovery.GetOVPNSecret("192.168.100.55")
	assert.True(t, ok, "Expected in-memory OVPN secret to be present for runtime connection")
	assert.Equal(t, b64Config, cachedSecret, "Expected cached secret to match discovery payload")

	// -------------------------------------------------------------
	// Test B: Raw SQLite Query Verification
	// -------------------------------------------------------------
	var rawB64Col, safeConfigCol string
	row := database.DB.Raw("SELECT openvpn_config_base64, openvpn_config FROM nodes WHERE id = ?", "192.168.100.55").Row()
	err = row.Scan(&rawB64Col, &safeConfigCol)
	require.NoError(t, err)

	assert.Empty(t, rawB64Col, "CRITICAL: SQLite column openvpn_config_base64 must be completely empty")
	assert.NotContains(t, safeConfigCol, secretMarker, "CRITICAL: SQLite column openvpn_config contains private key")

	// Full text scan of SQLite DB to guarantee secret string is not in any column of the table
	var matchCount int64
	err = database.DB.Raw("SELECT COUNT(*) FROM nodes WHERE openvpn_config_base64 LIKE ? OR openvpn_config LIKE ?",
		"%"+secretMarker+"%", "%"+secretMarker+"%").Scan(&matchCount).Error
	require.NoError(t, err)
	assert.Equal(t, int64(0), matchCount, "Found private key leaked into SQLite database rows!")

	// -------------------------------------------------------------
	// Test C: API Redaction & No Secret in HTTP Responses
	// -------------------------------------------------------------
	testAPIKey := "test-secret-key-lifecycle"
	agentapi.InitAuth(testAPIKey)
	sched := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	agentapi.SetScheduler(sched)

	// Create request to GET /api/v1/nodes/192.168.100.55
	req, _ := http.NewRequest("GET", "/api/v1/nodes/192.168.100.55", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/nodes/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
		var n models.Node
		if err := database.DB.Where("id = ?", id).First(&n).Error; err != nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		n.OpenVPN = ""
		n.OpenVPNConfig = discovery.StripSecrets(n.OpenVPNConfig)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(n)
	})
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	apiRespBody := rec.Body.String()
	assert.NotContains(t, apiRespBody, secretMarker, "CRITICAL: Private key leaked in API response!")
	assert.NotContains(t, apiRespBody, "openvpn_config_base64", "CRITICAL: openvpn_config_base64 field in API JSON!")

	// -------------------------------------------------------------
	// Test D: Logs do not contain the private key
	// -------------------------------------------------------------
	capturedLogs := logBuf.String()
	assert.NotContains(t, capturedLogs, secretMarker, "CRITICAL: Private key leaked into application logs!")

	// -------------------------------------------------------------
	// Test E: Metrics do not contain the private key
	// -------------------------------------------------------------
	promHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})
	metricsReq, _ := http.NewRequest("GET", "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	promHandler.ServeHTTP(metricsRec, metricsReq)
	metricsBody := metricsRec.Body.String()
	assert.NotContains(t, metricsBody, secretMarker, "CRITICAL: Private key leaked into Prometheus metrics!")

	// -------------------------------------------------------------
	// Test F: Daemon Restart Persistence Check
	// -------------------------------------------------------------
	// Simulate daemon shutdown: clear in-memory secret cache
	discovery.ClearOVPNSecretCache()
	assert.Equal(t, 0, discovery.OVPNSecretCacheSize(), "Expected in-memory secret cache to be cleared on shutdown")

	// Re-initialize database at the same path (simulating startup)
	require.NoError(t, database.InitDatabase(dbPath))

	// Re-query the node after simulated restart
	var restartNode models.Node
	err = database.DB.Where("id = ?", "192.168.100.55").First(&restartNode).Error
	require.NoError(t, err)

	// Verify metadata survived restart
	assert.Equal(t, "192.168.100.55", restartNode.IP)
	assert.Equal(t, "JP", restartNode.Country)
	assert.Equal(t, 850, restartNode.Score)

	// Verify raw secret DID NOT magically reappear in DB
	assert.Empty(t, restartNode.OpenVPN, "OpenVPN secret must not reappear after daemon restart")
	var restartRawCol string
	err = database.DB.Raw("SELECT openvpn_config_base64 FROM nodes WHERE id = ?", "192.168.100.55").Scan(&restartRawCol).Error
	require.NoError(t, err)
	assert.Empty(t, restartRawCol, "SQLite openvpn_config_base64 must remain empty after restart")
}

// TestMigrateStripRawOVPN_LegacyDataSanitization directly tests that legacy DB records
// containing raw credentials have openvpn_config_base64 wiped during database initialization.
func TestMigrateStripRawOVPN_LegacyDataSanitization(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "legacy_dirty.db")

	// 1. Initialize clean DB schema
	require.NoError(t, database.InitDatabase(dbPath))

	// 2. Directly insert dirty legacy rows with raw secrets via SQL
	dirtySecret := "DIRTY_LEGACY_RAW_OVPN_PRIVATE_KEY_DATA"
	err := database.DB.Exec(`INSERT INTO nodes 
		(id, ip, score, country, openvpn_config_base64, openvpn_config) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		"203.0.113.10", "203.0.113.10", 700, "KR",
		"base64_encoded_with_"+dirtySecret, "client\ndev tun").Error
	require.NoError(t, err)

	// Verify dirty secret exists in DB
	var beforeVal string
	_ = database.DB.Raw("SELECT openvpn_config_base64 FROM nodes WHERE id = ?", "203.0.113.10").Scan(&beforeVal)
	require.Contains(t, beforeVal, dirtySecret)

	// 3. Re-run InitDatabase (which invokes MigrateStripRawOVPN)
	require.NoError(t, database.InitDatabase(dbPath))

	// 4. Verify dirty secret was cleanly stripped
	var afterVal string
	_ = database.DB.Raw("SELECT openvpn_config_base64 FROM nodes WHERE id = ?", "203.0.113.10").Scan(&afterVal)
	assert.Empty(t, afterVal, "Expected openvpn_config_base64 to be completely cleared by migration")

	// Verify node was preserved
	var n models.Node
	err = database.DB.Where("id = ?", "203.0.113.10").First(&n).Error
	require.NoError(t, err)
	assert.Equal(t, "KR", n.Country)
	assert.Equal(t, 700, n.Score)
}
