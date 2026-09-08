package main

import (
	"log"
	"os"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/region"
	"gorm.io/gorm/clause"
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
}
