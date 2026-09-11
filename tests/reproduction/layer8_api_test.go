package reproduction

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/agentapi"
	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/stretchr/testify/require"
)

func TestLayer8_AgentAPI_TLSAndAuth(t *testing.T) {
	repEngine := reputation.NewEngineWithConfig(reputation.EngineConfig{
		FailurePolicy: "conservative",
		CacheTTL:      24 * time.Hour,
	})
	regConfig := config.RegionConfig{Primary: "JP"}
	sched := scheduler.NewScheduler(3, 2, repEngine, regConfig)

	apiKey := "test-secret-token-12345"
	server := agentapi.StartServerWithAddr("127.0.0.1", 60123, sched, apiKey)
	require.NotNil(t, server)
	defer server.Close()

	// Allow server to bind and start TLS listener
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 3 * time.Second,
	}

	// 1. Test unauthenticated request -> expect 401
	resp, err := client.Get("https://127.0.0.1:60123/api/v1/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// 2. Test authenticated endpoint with valid token
	reqAuth, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:60123/api/v1/status", nil)
	require.NoError(t, err)
	reqAuth.Header.Set("Authorization", "Bearer "+apiKey)
	respAuth, err := client.Do(reqAuth)
	require.NoError(t, err)
	defer respAuth.Body.Close()
	require.Equal(t, http.StatusOK, respAuth.StatusCode)

	// 2. Test authenticated endpoint without token -> expect 401
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:60123/api/v1/client-config/all", nil)
	require.NoError(t, err)
	respNoAuth, err := client.Do(req)
	require.NoError(t, err)
	defer respNoAuth.Body.Close()
	require.Equal(t, http.StatusUnauthorized, respNoAuth.StatusCode)

	// 3. Test authenticated endpoint with wrong token -> expect 403
	req.Header.Set("Authorization", "Bearer invalid-token")
	respBadAuth, err := client.Do(req)
	require.NoError(t, err)
	defer respBadAuth.Body.Close()
	require.Equal(t, http.StatusForbidden, respBadAuth.StatusCode)

	// 4. Test authenticated endpoint with valid token
	req.Header.Set("Authorization", "Bearer "+apiKey)
	respAuthClient, err := client.Do(req)
	require.NoError(t, err)
	defer respAuthClient.Body.Close()
	// When Xray supervisor is not running, expect 400 fail-closed
	require.True(t, respAuthClient.StatusCode == http.StatusBadRequest || respAuthClient.StatusCode == http.StatusOK)
}
