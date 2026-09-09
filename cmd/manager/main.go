package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/NaNA1337/super-proxy/internal/agentapi"
	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/metrics"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/routing"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/NaNA1337/super-proxy/internal/xray"
	"gorm.io/gorm/clause"
)

func main() {
	log.Println("Starting Super-Proxy Egress Manager Daemon...")

	// P2: Routing Diagnostics Command
	if len(os.Args) > 1 && os.Args[1] == "diagnose" {
		if len(os.Args) > 2 && os.Args[2] == "routing" {
			routing.Diagnose()
			return
		}
		log.Println("Usage: super-proxy diagnose routing")
		return
	}

	// 0. Root privilege check — required for ip rule/route/iptables and OpenVPN
	if os.Geteuid() != 0 {
		log.Fatalf("FATAL: super-proxy must be run as root (needed for routing, iptables, and OpenVPN)")
	}

	// 1. Load Configuration
	cfgPath := "/etc/super-proxy/config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	// Fallback to local example if the system path doesn't exist
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
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
	err = database.InitDatabase(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 4. Initialize Reputation Engine with multi-provider support
	repEngine := reputation.NewEngineWithConfig(reputation.EngineConfig{
		FailurePolicy: cfg.Reputation.FailurePolicy,
		CacheTTL:      24 * time.Hour,
	})
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

		if abuseKey == "" && greyKey == "" && ipqsKey == "" && ipinfoKey == "" {
			repEngine.AddProvider(&reputation.NullProvider{})
			log.Println("[Reputation] Enabled but no provider API keys supplied; using NullProvider")
		}
	} else {
		log.Println("[Reputation] Engine disabled in config")
	}

	// 5. Initial Discovery (Bootstrap pool if empty)
	nodeUpsertColumns := []string{"score", "country", "country_long", "sessions", "uptime", "users", "message", "openvpn_config_base64", "last_seen"}
	nodes, err := discovery.FetchAndParseNodes(cfg.Discovery.URL)
	if err != nil {
		log.Printf("Warning: Failed initial VPN Gate fetch (will retry later): %v", err)
	} else {
		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(nodeUpsertColumns),
		}).Create(&nodes)
		log.Printf("Bootstrapped %d nodes into database.", len(nodes))
	}

	// 6. Initialize Xray Supervisor (Config generation, validation, execution, and health monitoring)
	xrayConfigPath := "configs/xray_config.json"
	log.Printf("Generating Xray static configuration to %s ...", xrayConfigPath)
	if err := xray.GenerateConfigWithOptions(xray.ConfigOptions{
		SlotCount:   3,
		ConfigPath:  xrayConfigPath,
		SocksListen: "127.0.0.1",
		SocksPort:   1080,
		ApiPort:     10085,
	}); err != nil {
		log.Fatalf("Failed to generate Xray config: %v", err)
	}

	xsup := xray.NewSupervisor(xrayConfigPath, 10085, "127.0.0.1", 1080, 3)
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
	go runPeriodicDiscovery(discoveryCtx, cfg.Discovery.URL, discoveryInterval, nodeUpsertColumns)
	log.Printf("Periodic discovery refresh configured every %v", discoveryInterval)

	// 10. Initialize Agent API
	apiKey := cfg.API.Key
	if apiKey == "" {
		apiKey = cfg.APIKey
	}
	apiServer := agentapi.StartServerWithAddr(cfg.API.Listen, cfg.API.Port, sched, apiKey)
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

	// e. Teardown global firewall rules and leak protection
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
		select {
		case <-ctx.Done():
			log.Println("[Discovery] Periodic discovery loop stopped.")
			return
		case <-ticker.C:
			nodes, err := discovery.FetchAndParseNodes(url)
			if err != nil {
				log.Printf("[Discovery] Periodic fetch failed: %v", err)
				continue
			}

			database.DB.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(upsertCols),
			}).Create(&nodes)
			log.Printf("[Discovery] Refreshed %d nodes with updated scores and configs.", len(nodes))
		}
	}
}
