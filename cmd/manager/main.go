package main

import (
	"log"
	"os"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/health"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/region"
	"github.com/NaNA1337/super-proxy/internal/routing"
	"gorm.io/gorm/clause"
	"context"
	"time"
)

func main() {
	log.Println("Starting Xray Egress Manager (Phase 1)")

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

	// 3. Discover Nodes
	nodes, err := discovery.FetchAndParseNodes(cfg.Discovery.URL)
	if err != nil {
		log.Fatalf("Failed to fetch nodes: %v", err)
	}
	log.Printf("Discovered %d nodes from VPN Gate", len(nodes))

	// 4. Region Filter
	minRequired := 10 // Example requirement
	filteredNodes := region.FilterNodes(nodes, cfg.Region, minRequired)
	log.Printf("Filtered down to %d nodes based on region policy (Primary: %s)", len(filteredNodes), cfg.Region.Primary)

	// 5. Save to Database
	// We use clause.OnConflict to update existing nodes or insert new ones
	result := database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"score", "ping", "speed", "uptime", "sessions", "last_seen"}),
	}).Create(&filteredNodes)

	if result.Error != nil {
		log.Fatalf("Failed to save nodes to database: %v", result.Error)
	}

	log.Printf("Successfully saved/updated %d nodes in SQLite database", result.RowsAffected)
	log.Println("Phase 1 initialization complete.")

	// PHASE 2 TEST
	log.Println("--- Starting Phase 2 Test: OpenVPN Lifecycle ---")
	if len(filteredNodes) > 0 {
		testNode := &filteredNodes[0]
		
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		log.Printf("Spawning tunnel for node %s (%s)", testNode.ID, testNode.Country)
		tunnel, err := openvpn.StartTunnel(ctx, 0, testNode)
		if err != nil {
			log.Printf("Failed to start tunnel: %v", err)
		} else {
			log.Printf("Tunnel spawned! Interface: %s. Wait 5s for interface to come up...", tunnel.Interface)
			time.Sleep(5 * time.Second)

			// PHASE 3: Apply Routing
			log.Printf("Applying policy routing for slot 0...")
			if err := routing.SetupSlotRouting(0, tunnel.Interface); err != nil {
				log.Printf("Failed to setup routing (expected if tun0 not ready): %v", err)
			} else {
				log.Printf("Routing applied successfully.")
			}

			// Try a health check (it will likely fail if openvpn didn't fully establish, but tests the logic)
			log.Printf("Running health check on %s...", tunnel.Interface)
			ctxTimeout, cancelTimeout := context.WithTimeout(ctx, 10*time.Second)
			ok, dur, err := health.CheckTunnelConnectivity(ctxTimeout, tunnel.Interface, "http://1.1.1.1")
			cancelTimeout()
			
			if err != nil {
				log.Printf("Health check failed (expected if VPN not connected): %v", err)
			} else {
				log.Printf("Health check result: ok=%v, duration=%v", ok, dur)
			}

			log.Printf("Stopping tunnel and clearing routing...")
			routing.ClearSlotRouting(0)
			tunnel.Stop()
			time.Sleep(1 * time.Second)
			log.Printf("Tunnel stopped.")
		}
	} else {
		log.Println("No nodes found, skipping OpenVPN/Routing tests.")
	}
	
	log.Println("Phase 3 test complete.")
}
