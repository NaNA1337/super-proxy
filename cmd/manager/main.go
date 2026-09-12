package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/NaNA1337/super-proxy/internal/agentapi"
	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/metrics"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/routing"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/NaNA1337/super-proxy/internal/xray"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var version = "dev"
var commit = "unknown"

func runPreflightChecks() error {
	// 1. Kernel TUN device
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("kernel TUN device (/dev/net/tun) is not accessible: %w", err)
	}

	// 2. iproute2
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("required system tool 'ip' (iproute2) is not found in PATH: %w", err)
	}

	// 3. iptables
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("required system tool 'iptables' is not found in PATH: %w", err)
	}

	// 4. openvpn binary
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("required system tool 'openvpn' is not found in PATH: %w", err)
	}

	// 5. xray binary
	if _, err := exec.LookPath("xray"); err != nil {
		return fmt.Errorf("required system tool 'xray' is not found in PATH: %w", err)
	}

	return nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("super-proxy %s (%s)\n", version, commit)
		return
	}
	log.Printf("Starting Super-Proxy %s (%s)...", version, commit)

	// Diagnostics Commands
	if len(os.Args) > 1 && os.Args[1] == "diagnose" {
		if len(os.Args) > 2 && os.Args[2] == "environment" {
			routing.DiagnoseEnvironment()
			return
		}
		if len(os.Args) > 2 && os.Args[2] == "routing" {
			routing.Diagnose()
			return
		}
		log.Println("Usage: super-proxy diagnose [routing|environment]")
		return
	}

	// 0. Root privilege check — required for ip rule/route/iptables and OpenVPN
	if os.Geteuid() != 0 {
		log.Fatalf("FATAL: super-proxy must be run as root (needed for routing, iptables, and OpenVPN)")
	}

	// Preflight validation of system dependencies
	if err := runPreflightChecks(); err != nil {
		log.Fatalf("FATAL PREFLIGHT CHECK FAILED: %v", err)
	}

	// 1. Load Configuration
	cfgPath := "/etc/super-proxy/config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	// Only the implicit default may fall back to the development example.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) && len(os.Args) == 1 {
		cfgPath = "configs/config.example.yaml"
		log.Printf("Warning: using fallback config %s (production should use /etc/super-proxy/config.yaml)", cfgPath)
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Loaded config: Region Primary=%s", cfg.Region.Primary)

	// 2. Write PID file
	pidFile := "/var/run/super-proxy.pid"
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		log.Printf("Warning: failed to write PID file %s: %v", pidFile, err)
	} else {
		defer os.Remove(pidFile)
	}

	// 3. Initialize Database
	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "xray_manager.db"
	}
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			log.Printf("Warning: failed to create directory for database %s: %v", dir, err)
		}
	}
	err = database.InitDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 4. Initialize Reputation Engine with multi-provider support
	repEngine := reputation.NewEngineWithConfig(reputation.EngineConfig{
		FailurePolicy: cfg.Reputation.FailurePolicy,
		CacheTTL:      24 * time.Hour,
	})
	repEngine.SetDB(database.DB)
	repEngine.AddProvider(reputation.NewOwnershipProvider())
	log.Println("[Reputation] Built-in ASN ownership provider registered (no API key required)")
	if cfg.Reputation.Enabled {
		// AbuseIPDB
		abuseKey := cfg.Reputation.AbuseIPDBKey
		if abuseKey == "" {
			abuseKey = cfg.Reputation.APIKey
		}
		if abuseKey == "" {
			abuseKey = os.Getenv("XRAY_MANAGER_ABUSEIPDB_KEY")
		}
		if abuseKey != "" {
			repEngine.AddProvider(reputation.NewAbuseIPDBProvider(abuseKey))
			log.Println("[Reputation] AbuseIPDB provider registered")
		}

		// GreyNoise
		greyKey := cfg.Reputation.GreyNoiseKey
		if greyKey == "" {
			greyKey = os.Getenv("XRAY_MANAGER_GREYNOISE_KEY")
		}
		if greyKey != "" {
			repEngine.AddProvider(reputation.NewGreyNoiseProvider(greyKey))
			log.Println("[Reputation] GreyNoise provider registered")
		}

		// IPQS
		ipqsKey := cfg.Reputation.IPQSKey
		if ipqsKey == "" {
			ipqsKey = os.Getenv("XRAY_MANAGER_IPQS_KEY")
		}
		if ipqsKey != "" {
			repEngine.AddProvider(reputation.NewIPQSProvider(ipqsKey))
			log.Println("[Reputation] IPQS provider registered")
		}

		// IPInfo
		ipinfoKey := cfg.Reputation.IPInfoKey
		if ipinfoKey == "" {
			ipinfoKey = os.Getenv("XRAY_MANAGER_IPINFO_KEY")
		}
		if ipinfoKey != "" {
			repEngine.AddProvider(reputation.NewIPInfoProvider(ipinfoKey))
			log.Println("[Reputation] IPInfo provider registered")
		}

	} else {
		log.Println("[Reputation] Keyed threat providers disabled; built-in ASN ownership checks remain active")
	}

	// Initial discovery runs in the background after local services are ready.

	// 6. Initialize Xray Supervisor (Config generation, validation, execution, and health monitoring)
	xrayConfigPath := cfg.Xray.ConfigPath
	if xrayConfigPath == "" {
		if cfgDir := filepath.Dir(cfgPath); cfgDir != "" && cfgDir != "." {
			xrayConfigPath = filepath.Join(cfgDir, "xray_config.json")
		} else {
			xrayConfigPath = "configs/xray_config.json"
		}
	}
	vlessCfg := cfg.Xray.Vless
	if os.Getenv("XRAY_VLESS_ENABLED") == "true" {
		vlessCfg.Enabled = true
	}
	if vlessCfg.Enabled {
		if err := xray.NormalizeVlessConfig(&vlessCfg); err != nil {
			log.Fatalf("Failed to normalize VLESS config: %v", err)
		}
		agentapi.SetActiveVlessConfig(&vlessCfg)
		log.Printf("VLESS Reality enabled: port=%d, dest=%s, SNI=%v, flow=%s, fingerprint=%s, outbound_only_443=%v",
			vlessCfg.Port, vlessCfg.Dest, vlessCfg.ServerNames, vlessCfg.Flow, vlessCfg.Fingerprint, vlessCfg.OutboundOnlyPort443)
	}

	if err := xray.GenerateConfigWithOptions(xray.ConfigOptions{
		SlotCount:   3,
		ConfigPath:  xrayConfigPath,
		SocksListen: "127.0.0.1",
		SocksPort:   1080,
		ApiPort:     10085,
		Vless:       vlessCfg,
	}); err != nil {
		log.Fatalf("Failed to generate Xray config: %v", err)
	}

	xsup := xray.NewSupervisor(xrayConfigPath, 10085, "127.0.0.1", 1080, 3)
	if vlessCfg.Enabled && vlessCfg.PublicAddress != "" {
		if err := xray.ValidatePublicAddress(vlessCfg.PublicAddress); err != nil {
			log.Fatalf("Invalid VLESS public address: %v", err)
		}
		if err := xsup.SetPublicAddress(vlessCfg.PublicAddress); err != nil {
			log.Fatalf("Failed to set VLESS public address: %v", err)
		}
	}
	xsup.OnRestart = func(attempt int) {
		metrics.XrayRestarts.Inc()
	}
	if err := xsup.ValidateConfig(xrayConfigPath); err != nil {
		log.Fatalf("Xray configuration validation failed: %v", err)
	}
	if err := xsup.Start(); err != nil {
		log.Fatalf("Failed to start Xray supervisor: %v", err)
	}
	log.Println("Xray Supervisor started and process ready.")

	// 7. Initialize Global Policy Routing and Custom Iptables Chains
	if err := routing.InitGlobalIptables(); err != nil {
		log.Printf("Warning: Failed to initialize global iptables: %v", err)
	}
	if err := routing.EnableDNSLeakProtection(); err != nil {
		log.Printf("Warning: Failed to enable DNS leak protection: %v", err)
	}
	if err := routing.EnableIPv6LeakProtection(); err != nil {
		log.Printf("Warning: Failed to enable IPv6 leak protection: %v", err)
	}

	// 8. Initialize Scheduler (Manages OpenVPN tunnels, FSM, and active slots)
	sched := scheduler.NewScheduler(3, 2, repEngine, cfg.Region)
	sched.ScoringEngine = scheduler.NewScoringEngine(cfg.Scoring)
	sched.SetSpeedTestConfig(cfg.SpeedTest)
	sched.SetXraySupervisor(xsup)
	sched.Start()
	log.Println("Scheduler Engine started.")

	// 9. Start periodic discovery refresh
	discoveryInterval := time.Duration(cfg.Discovery.Interval) * time.Minute
	if discoveryInterval < time.Minute {
		discoveryInterval = 15 * time.Minute
	}
	discoveryCtx, cancelDiscovery := context.WithCancel(context.Background())
	go runPeriodicDiscovery(discoveryCtx, cfg.Discovery.URL, discoveryInterval, models.NodeUpsertColumns)
	log.Printf("Periodic discovery refresh configured every %v", discoveryInterval)

	// 10. Initialize Agent API
	apiKey := cfg.API.Key
	if apiKey == "" {
		apiKey = cfg.APIKey
	}
	agentapi.SetVersion(version)
	apiServer := agentapi.StartServerWithTLSPaths(cfg.API.Listen, cfg.API.Port, sched, apiKey,
		filepath.Join(filepath.Dir(cfgPath), "cert.pem"), filepath.Join(filepath.Dir(cfgPath), "key.pem"))
	log.Printf("Agent API Server listening on %s:%d.", cfg.API.Listen, cfg.API.Port)

	// 11. Wait for Interrupt for Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Interrupt signal received. Initiating graceful shutdown...")

	// 12. Shutdown sequence:
	// a. Stop periodic discovery
	cancelDiscovery()

	// b. Stop API server (no new commands accepted)
	if apiServer != nil {
		if err := apiServer.Close(); err != nil {
			log.Printf("API Server shutdown error: %v", err)
		}
	}

	// c. Stop scheduler (drains and stops all OpenVPN tunnels, cleans per-slot routing)
	sched.Stop()

	// d. Stop Xray supervisor
	if xsup != nil {
		xsup.Stop()
	}

	// e. Teardown slot policy routing, global firewall rules and leak protection
	for i := 0; i < 5; i++ {
		routing.TeardownSlotRouting(i)
	}
	routing.ClearGlobalIptables()
	routing.DisableDNSLeakProtection()
	routing.DisableIPv6LeakProtection()

	log.Println("Super-Proxy Daemon cleanly exited.")
}

// runPeriodicDiscovery fetches VPN Gate data on a regular interval and upserts into DB.
func runPeriodicDiscovery(ctx context.Context, url string, interval time.Duration, upsertCols []string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// Fetch once immediately, then on the configured interval. Never gate API startup on the network.
		nodes, err := discovery.FetchAndParseNodes(url)
		if err != nil {
			log.Printf("[Discovery] Fetch failed (will retry): %v", err)
		} else if len(nodes) > 0 {
			txErr := database.DB.Transaction(func(tx *gorm.DB) error {
				return tx.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "id"}},
					DoUpdates: clause.AssignmentColumns(upsertCols),
				}).Create(&nodes).Error
			})
			if txErr != nil {
				log.Printf("[Discovery] Refresh failed: %v", txErr)
			} else {
				log.Printf("[Discovery] Refreshed %d nodes", len(nodes))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
