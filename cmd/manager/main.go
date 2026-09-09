package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

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

	// 1. Load Configuration
	cfgPath := "configs/config.example.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Loaded config: Region Primary=%s", cfg.Region.Primary)

	// 2. Initialize Database
	err = database.InitDatabase(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 3. Initialize Reputation Engine
	repEngine := reputation.NewEngine()
	// TODO: Configure actual provider if API keys present in cfg

	// 4. Initial Discovery (Bootstrap pool if empty)
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

	// 5. Initialize Xray Config (Create dynamic load balancing outbounds)
	xrayConfigPath := "configs/xray_config.json"
	log.Printf("Generating Xray static configuration to %s ...", xrayConfigPath)
	if err := xray.GenerateConfig(3, xrayConfigPath); err != nil {
		log.Fatalf("Failed to generate Xray config: %v", err)
	}

	// 6. Initialize Scheduler (which handles OpenVPN and Routing)
	// We run 3 active exits and 2 standby tunnels for fast failover
	sched := scheduler.NewScheduler(3, 2, repEngine)
	sched.Start()
	log.Println("Scheduler Engine started.")

	// 7. Initialize Agent API
	agentapi.InitAuth()
	apiServer := agentapi.StartServer(60000, sched)
	log.Println("Agent API Server listening on port 60000.")

	// 8. Wait for Interrupt for Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Interrupt signal received. Initiating graceful shutdown...")

	// 9. Shutdown sequence
	// Shutdown API first so no new switch commands come in
	if apiServer != nil {
		if err := apiServer.Close(); err != nil {
			log.Printf("API Server shutdown error: %v", err)
		}
	}
	
	// Stop scheduler and all its managed tunnels and routes
	sched.Stop()
	
	log.Println("Super-Proxy Daemon cleanly exited.")
}
