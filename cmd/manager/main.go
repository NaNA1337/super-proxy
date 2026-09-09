package main

import (
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

	// 4. Initialize Reputation Engine with providers
	repEngine := reputation.NewEngine()
	if cfg.Reputation.Enabled {
		apiKey := cfg.Reputation.APIKey
		if apiKey == "" {
			apiKey = os.Getenv("XRAY_MANAGER_ABUSEIPDB_KEY")
		}
		if apiKey != "" {
			repEngine.AddProvider(reputation.NewAbuseIPDBProvider(apiKey))
			log.Println("Reputation engine: AbuseIPDB provider registered")
		} else {
			// Use NullProvider so reputation path is exercised and logged, but doesn't block
			repEngine.AddProvider(&reputation.NullProvider{})
			log.Println("Reputation engine: enabled but no API key — using NullProvider (all IPs pass)")
		}
	} else {
		log.Println("Reputation engine: disabled in config")
	}

	// 5. Initial Discovery (Bootstrap pool if empty)
	nodes, err := discovery.FetchAndParseNodes(cfg.Discovery.URL)
	if err != nil {
		log.Printf("Warning: Failed initial VPN Gate fetch (will retry later): %v", err)
	} else {
		// Save to Database
		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"country", "country_long", "sessions", "last_seen"}),
		}).Create(&nodes)
		log.Printf("Bootstrapped %d nodes into database.", len(nodes))
	}

	// 6. Initialize Xray Config (Create dynamic load balancing outbounds)
	xrayConfigPath := "configs/xray_config.json"
	log.Printf("Generating Xray static configuration to %s ...", xrayConfigPath)
	if err := xray.GenerateConfig(3, xrayConfigPath); err != nil {
		log.Fatalf("Failed to generate Xray config: %v", err)
	}

	// 7. Enable leak protection before starting tunnels
	if err := routing.EnableDNSLeakProtection(); err != nil {
		log.Printf("Warning: Failed to enable DNS leak protection: %v", err)
	}
	if err := routing.EnableIPv6LeakProtection(); err != nil {
		log.Printf("Warning: Failed to enable IPv6 leak protection: %v", err)
	}

	// 8. Initialize Scheduler (which handles OpenVPN and Routing)
	// We run 3 active exits and 2 standby tunnels for fast failover
	sched := scheduler.NewScheduler(3, 2, repEngine, cfg.Region)
	sched.Start()
	log.Println("Scheduler Engine started.")

	// 9. Start periodic discovery refresh
	discoveryInterval := time.Duration(cfg.Discovery.Interval) * time.Minute
	if discoveryInterval < time.Minute {
		discoveryInterval = 15 * time.Minute
	}
	go runPeriodicDiscovery(cfg.Discovery.URL, discoveryInterval)
	log.Printf("Periodic discovery refresh every %v", discoveryInterval)

	// 10. Initialize Agent API
	apiServer := agentapi.StartServer(60000, sched)
	log.Println("Agent API Server listening on port 60000.")

	// 11. Wait for Interrupt for Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Interrupt signal received. Initiating graceful shutdown...")

	// 12. Shutdown sequence
	// Shutdown API first so no new switch commands come in
	if apiServer != nil {
		if err := apiServer.Close(); err != nil {
			log.Printf("API Server shutdown error: %v", err)
		}
	}

	// Stop scheduler and all its managed tunnels and routes
	sched.Stop()

	// Disable leak protection
	routing.DisableDNSLeakProtection()
	routing.DisableIPv6LeakProtection()

	log.Println("Super-Proxy Daemon cleanly exited.")
}

// runPeriodicDiscovery fetches VPN Gate data on a regular interval and upserts into DB.
func runPeriodicDiscovery(url string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		nodes, err := discovery.FetchAndParseNodes(url)
		if err != nil {
			log.Printf("[Discovery] Periodic fetch failed: %v", err)
			continue
		}

		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"country", "country_long", "sessions", "last_seen"}),
		}).Create(&nodes)
		log.Printf("[Discovery] Refreshed %d nodes.", len(nodes))
	}
}
