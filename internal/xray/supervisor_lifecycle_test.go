package xray_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/agentapi"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/xray"
)

// port443Mutex serializes tests that bind public TCP 443.
var port443Mutex sync.Mutex

func createTestVlessConfig(t *testing.T, apiPort, socksPort int) (string, xray.VlessConfig) {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, fmt.Sprintf("xray_vless_%d.json", apiPort))

	vlessCfg := xray.VlessConfig{
		Enabled:             true,
		Port:                443,
		UUID:                "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:                "xtls-rprx-vision",
		Dest:                "www.microsoft.com:443",
		ServerNames:         []string{"www.microsoft.com"},
		Fingerprint:         "chrome",
		PublicKey:           "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:            []string{"0123456789abcdef"},
		OutboundOnlyPort443: true,
	}
	if err := xray.NormalizeVlessConfig(&vlessCfg); err != nil {
		t.Fatalf("NormalizeVlessConfig failed: %v", err)
	}

	err := xray.GenerateConfigWithOptions(xray.ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     apiPort,
		SocksListen: "127.0.0.1",
		SocksPort:   socksPort,
		Vless:       vlessCfg,
	})
	if err != nil {
		t.Fatalf("GenerateConfigWithOptions failed: %v", err)
	}

	return configPath, vlessCfg
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// Test 1: READY 注册 endpoint
// 启动真实 Xray Supervisor。等待 READY，确认 GetRuntimeVlessEndpoint() 存在且符合不变量。
func TestSupervisor_Lifecycle_Test1_ReadyRegistersEndpoint(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node1.super-proxy.net")

	// Pre-condition: endpoint MUST be nil before READY
	if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
		t.Fatalf("expected nil endpoint before start, got %+v", ep)
	}

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}
	defer sup.Stop()

	// Verify READY state
	state, _, _ := sup.GetState()
	if state != xray.StateRunning {
		t.Fatalf("expected StateRunning, got %s", state)
	}

	// Verify endpoint registered
	ep, err := xray.GetRuntimeVlessEndpoint()
	if err != nil || ep == nil {
		t.Fatalf("expected runtime endpoint to be registered when READY, got err: %v", err)
	}
	if ep.Port != 443 {
		t.Errorf("expected Port == 443, got %d", ep.Port)
	}
	if ep.Network != "tcp" {
		t.Errorf("expected Network == 'tcp', got %s", ep.Network)
	}
	if ep.Protocol != "vless" {
		t.Errorf("expected Protocol == 'vless', got %s", ep.Protocol)
	}
	if !ep.TLS {
		t.Errorf("expected TLS == true, got false")
	}
	if ep.Address != "node1.super-proxy.net" {
		t.Errorf("expected Address == 'node1.super-proxy.net', got %s", ep.Address)
	}

	// Health check must pass on READY supervisor
	if err := sup.CheckHealth(); err != nil {
		t.Errorf("expected CheckHealth to pass on READY supervisor, got: %v", err)
	}
}

// Test 2: process crash 自动清除
// 启动 Xray，等待 READY，确认 GetRuntimeVlessEndpoint() != nil。
// 主动终止 Xray child process，等待 Supervisor 发现 process exit。
// 最终必须：GetRuntimeVlessEndpoint() == nil
// 然后 /api/v1/export/clash, /api/v1/export/singbox, /api/v1/export/xray, /api/v1/export/sub 全部必须 fail-closed。
func TestSupervisor_Lifecycle_Test2_CrashClearsEndpointAndExportsFailClosed(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	_ = database.InitDatabase(":memory:")
	authKey := "test-secret-api-key-lifecycle"
	agentapi.InitAuth(authKey)
	apiHandler := agentapi.NewHandler(nil, authKey)

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, vlessCfg := createTestVlessConfig(t, apiPort, socksPort)
	agentapi.SetActiveVlessConfig(&vlessCfg)

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node2.super-proxy.net")

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}
	defer sup.Stop()

	// Confirm READY and endpoint registered
	ep, err := xray.GetRuntimeVlessEndpoint()
	if err != nil || ep == nil {
		t.Fatalf("expected endpoint registered, got: %v", err)
	}

	// Verify export initially succeeds
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/export/clash", nil)
	req.Header.Set("Authorization", "Bearer "+authKey)
	apiHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK before crash, got %d: %s", rec.Code, rec.Body.String())
	}

	// Actively kill child process to simulate crash
	if err := sup.KillCurrentProcess(); err != nil {
		t.Fatalf("failed to kill child process: %v", err)
	}

	// Wait for supervisor crash detection to clear runtime endpoint
	cleared := false
	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		if _, err := xray.GetRuntimeVlessEndpoint(); err != nil {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatalf("expected runtime endpoint to be CLEARED immediately upon crash")
	}

	// Now verify ALL export endpoints fail-closed when crashed
	endpoints := []string{
		"/api/v1/client-config/all",
		"/api/v1/export/clash",
		"/api/v1/export/singbox",
		"/api/v1/export/xray",
		"/api/v1/export/sub?token=" + authKey,
	}

	for _, path := range endpoints {
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", path, nil)
		if !strings.Contains(path, "token=") {
			req.Header.Set("Authorization", "Bearer "+authKey)
		}
		apiHandler.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Errorf("FAIL: %s returned 200 OK while crashed! Must fail-closed. Body: %s", path, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "localhost") {
			t.Errorf("FAIL: %s leaked localhost/127.0.0.1 during crash: %s", path, body)
		}
	}
}

// Test 3: normal Stop 自动清除
// READY 后 Supervisor.Stop()，最终 GetRuntimeVlessEndpoint() == nil。
// 连续调用 Stop() 验证幂等性。
func TestSupervisor_Lifecycle_Test3_NormalStopClearsEndpoint(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node3.super-proxy.net")

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}

	if _, err := xray.GetRuntimeVlessEndpoint(); err != nil {
		t.Fatalf("expected endpoint when READY: %v", err)
	}

	// Normal Stop
	if err := sup.Stop(); err != nil {
		t.Fatalf("sup.Stop failed: %v", err)
	}

	// Must be cleared
	if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
		t.Errorf("expected endpoint to be nil after Stop(), got: %+v", ep)
	}

	// Idempotent Stop call
	if err := sup.Stop(); err != nil {
		t.Errorf("second sup.Stop() failed: %v", err)
	}
	if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
		t.Errorf("expected endpoint to remain nil after second Stop(), got: %+v", ep)
	}
}

// Test 4: startup failure 不注册 endpoint
// 让 Xray 启动失败（invalid config, invalid binary, occupied port）。
// 最终 GetRuntimeVlessEndpoint() == nil。绝不能出现 Xray 没起来但 export 可以生成 VLESS。
func TestSupervisor_Lifecycle_Test4_StartupFailureNoEndpoint(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	_ = database.InitDatabase(":memory:")
	authKey := "test-secret-api-key-lifecycle"
	agentapi.InitAuth(authKey)
	apiHandler := agentapi.NewHandler(nil, authKey)

	// Sub-test 4a: Invalid configuration syntax
	t.Run("InvalidConfig", func(t *testing.T) {
		xray.ClearRuntimeVlessEndpoint()
		tempDir := t.TempDir()
		badCfg := filepath.Join(tempDir, "bad.json")
		_ = os.WriteFile(badCfg, []byte(`{"inbounds": [malformed json`), 0600)

		sup := xray.NewSupervisor(badCfg, 10590, "127.0.0.1", 10890, 2)
		_ = sup.SetPublicAddress("node4a.super-proxy.net")
		err := sup.Start()
		if err == nil {
			sup.Stop()
			t.Fatalf("expected Start() to fail on bad config")
		}

		if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
			t.Errorf("endpoint was registered despite bad config startup failure: %+v", ep)
		}

		// Assert export fails closed
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1/export/clash", nil)
		req.Header.Set("Authorization", "Bearer "+authKey)
		apiHandler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("export succeeded despite startup failure!")
		}
	})

	// Sub-test 4b: Invalid binary path
	t.Run("InvalidBinary", func(t *testing.T) {
		xray.ClearRuntimeVlessEndpoint()
		apiPort := getFreePort(t)
		socksPort := getFreePort(t)
		cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

		sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
		sup.SetBinaryPath("/usr/bin/nonexistent_xray_binary")
		_ = sup.SetPublicAddress("node4b.super-proxy.net")

		err := sup.Start()
		if err == nil {
			sup.Stop()
			t.Fatalf("expected Start() to fail on missing binary")
		}

		if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
			t.Errorf("endpoint was registered despite missing binary: %+v", ep)
		}
	})

	// Sub-test 4c: Occupied API port causes startup/readiness failure
	t.Run("OccupiedPort", func(t *testing.T) {
		xray.ClearRuntimeVlessEndpoint()
		apiPort := getFreePort(t)
		socksPort := getFreePort(t)
		cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

		// Occupy the API port
		blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", apiPort))
		if err != nil {
			t.Fatalf("failed to occupy port: %v", err)
		}
		defer blocker.Close()

		sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
		sup.SetReadyTimeout(2 * time.Second)
		_ = sup.SetPublicAddress("node4c.super-proxy.net")

		startErr := sup.Start()
		if startErr == nil {
			sup.Stop()
			t.Fatalf("expected Start() to fail when API port is occupied")
		}

		if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
			t.Errorf("endpoint was registered despite occupied port failure: %+v", ep)
		}
	})
}

// Test 5: readiness timeout 不注册
// 让 process 存活但是无法通过 readiness。最终 GetRuntimeVlessEndpoint() == nil。
func TestSupervisor_Lifecycle_Test5_ReadinessTimeoutNoEndpoint(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "readiness_dummy.json")
	_ = os.WriteFile(cfgPath, []byte(`{}`), 0600)

	// Create a dummy wrapper that passes ValidateConfig ("-test") but sleeps on run
	wrapperScript := filepath.Join(tempDir, "mock_xray.sh")
	scriptContent := "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"-test\" ]; then exit 0; fi\ndone\nexec /bin/sleep 5\n"
	if err := os.WriteFile(wrapperScript, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write wrapper script: %v", err)
	}

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	sup.SetReadyTimeout(2 * time.Second)
	sup.SetBinaryPath(wrapperScript)
	_ = sup.SetPublicAddress("node5.super-proxy.net")

	startErr := sup.Start()
	if startErr == nil {
		sup.Stop()
		t.Fatalf("expected Start() to fail with readiness timeout")
	}

	if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
		t.Fatalf("FAIL: endpoint was registered despite readiness timeout: %+v", ep)
	}
}

// Test 6: restart lifecycle
// READY -> endpoint exists -> restart -> endpoint disappears -> new Xray READY -> endpoint reappears.
// 并且不能出现旧 endpoint 在 restart 中长期残留。
func TestSupervisor_Lifecycle_Test6_RestartLifecycle(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node6.super-proxy.net")

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}
	defer sup.Stop()

	// 1. Initial READY: endpoint exists
	ep1, err := xray.GetRuntimeVlessEndpoint()
	if err != nil || ep1 == nil {
		t.Fatalf("expected endpoint registered, got: %v", err)
	}

	// 2. Trigger Restart()
	restartErr := sup.Restart()
	if restartErr != nil {
		t.Fatalf("sup.Restart failed: %v", restartErr)
	}

	// 3. After restart: endpoint must be restored and valid
	ep2, err := xray.GetRuntimeVlessEndpoint()
	if err != nil || ep2 == nil {
		t.Fatalf("expected endpoint to be restored after restart, got: %v", err)
	}
	if ep2.Port != 443 || ep2.Network != "tcp" || ep2.Protocol != "vless" || !ep2.TLS {
		t.Errorf("invalid endpoint after restart: %+v", ep2)
	}
}

// Test 7: context cancellation
// 启动 Supervisor，等待 READY，cancel context，等待 Supervisor 完全退出，最终 GetRuntimeVlessEndpoint() == nil。
func TestSupervisor_Lifecycle_Test7_ContextCancellation(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	ctx, cancel := context.WithCancel(context.Background())

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

	sup := xray.NewSupervisorWithContext(ctx, cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node7.super-proxy.net")

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}
	defer sup.Stop()

	if _, err := xray.GetRuntimeVlessEndpoint(); err != nil {
		t.Fatalf("expected endpoint when READY: %v", err)
	}

	// Cancel context
	cancel()

	// Wait for context watcher to clear endpoint and stop process
	cleared := false
	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		if _, err := xray.GetRuntimeVlessEndpoint(); err != nil {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Errorf("expected runtime endpoint to be CLEARED after context cancellation")
	}
}

// Test 8: concurrent export during restart
// 同时执行：restart Xray 以及大量 /api/v1/export/clash, /api/v1/export/singbox, /api/v1/export/xray, /api/v1/export/sub
// 允许出现：成功返回新 endpoint, fail-closed
// 但禁止：返回已经失效的旧 endpoint, 返回 localhost, 返回非 443, 返回部分更新 endpoint.
func TestSupervisor_Lifecycle_Test8_ConcurrentExportDuringRestart(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	_ = database.InitDatabase(":memory:")
	authKey := "test-secret-api-key-lifecycle"
	agentapi.InitAuth(authKey)
	apiHandler := agentapi.NewHandler(nil, authKey)

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, vlessCfg := createTestVlessConfig(t, apiPort, socksPort)
	agentapi.SetActiveVlessConfig(&vlessCfg)

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node8.super-proxy.net")

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}
	defer sup.Stop()

	// Run concurrent export callers while restarting
	var wg sync.WaitGroup
	stopExports := make(chan struct{})
	errCount := 0
	var countMu sync.Mutex

	exportPaths := []string{
		"/api/v1/client-config/all",
		"/api/v1/export/clash",
		"/api/v1/export/singbox",
		"/api/v1/export/xray",
		"/api/v1/export/sub?token=" + authKey,
	}

	workerCount := 10
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			path := exportPaths[workerID%len(exportPaths)]
			reqNum := 0
			for {
				select {
				case <-stopExports:
					return
				default:
				}
				reqNum++

				rec := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", path, nil)
				req.RemoteAddr = fmt.Sprintf("192.0.2.%d:12345", (workerID*20+reqNum)%240+1)
				if !strings.Contains(path, "token=") {
					req.Header.Set("Authorization", "Bearer "+authKey)
				}
				apiHandler.ServeHTTP(rec, req)

				body := rec.Body.String()
				checkBody := body
				if strings.Contains(path, "/export/sub") && rec.Code == http.StatusOK {
					if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body)); err == nil {
						checkBody = string(decoded)
					}
				}

				// Forbidden in ALL responses: server endpoint MUST NOT be localhost/127.0.0.1
				if strings.Contains(checkBody, "server: 127.0.0.1") || strings.Contains(checkBody, "server: localhost") ||
					strings.Contains(checkBody, `"server": "127.0.0.1"`) || strings.Contains(checkBody, `"server": "localhost"`) ||
					strings.Contains(checkBody, `"address": "127.0.0.1"`) || strings.Contains(checkBody, `"address": "localhost"`) ||
					strings.Contains(checkBody, "@127.0.0.1:") || strings.Contains(checkBody, "@localhost:") {
					t.Errorf("VIOLATION: export returned localhost/127.0.0.1 server endpoint! Body: %s", checkBody)
				}

				if rec.Code == http.StatusOK {
					// If 200 OK, MUST be port 443 and valid
					if !strings.Contains(checkBody, "443") {
						t.Errorf("VIOLATION: 200 OK export missing port 443: %s", checkBody)
					}
					if !strings.Contains(checkBody, "node8.super-proxy.net") {
						t.Errorf("VIOLATION: 200 OK export missing public address: %s", checkBody)
					}
				} else {
					// If fail-closed, count it
					countMu.Lock()
					errCount++
					countMu.Unlock()
				}
				time.Sleep(15 * time.Millisecond)
			}
		}(i)
	}

	// Trigger restart during active export traffic
	time.Sleep(50 * time.Millisecond)
	if err := sup.Restart(); err != nil {
		t.Fatalf("Restart failed during concurrent exports: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	close(stopExports)
	wg.Wait()

	// Verify that after restart completes, export returns 200 OK with valid endpoint
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/export/clash", nil)
	req.RemoteAddr = "192.0.2.250:12345"
	req.Header.Set("Authorization", "Bearer "+authKey)
	apiHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after restart finished, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Test CheckHealth failure clears runtime endpoint
func TestSupervisor_Lifecycle_CheckHealthFailureClearsEndpoint(t *testing.T) {
	port443Mutex.Lock()
	defer port443Mutex.Unlock()
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()

	apiPort := getFreePort(t)
	socksPort := getFreePort(t)
	cfgPath, _ := createTestVlessConfig(t, apiPort, socksPort)

	sup := xray.NewSupervisor(cfgPath, apiPort, "127.0.0.1", socksPort, 2)
	_ = sup.SetPublicAddress("node-health.super-proxy.net")

	if err := sup.Start(); err != nil {
		t.Fatalf("sup.Start failed: %v", err)
	}
	defer sup.Stop()

	if err := sup.CheckHealth(); err != nil {
		t.Fatalf("CheckHealth failed when running: %v", err)
	}

	// Kill child process
	_ = sup.KillCurrentProcess()
	time.Sleep(100 * time.Millisecond)

	// CheckHealth should fail and clear runtime endpoint
	if err := sup.CheckHealth(); err == nil {
		t.Errorf("expected CheckHealth to fail after process killed")
	}

	if ep, err := xray.GetRuntimeVlessEndpoint(); err == nil || ep != nil {
		t.Errorf("expected endpoint to be cleared on CheckHealth failure, got: %+v", ep)
	}
}
