package database

import (
	"log"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

// InitDatabase initializes the SQLite database and performs migrations
func InitDatabase(dbPath string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return err
	}

	// Auto-migrate models
	err = DB.AutoMigrate(&models.Node{}, &models.PrefixIntelligence{})
	if err != nil {
		return err
	}

	log.Printf("Database initialized successfully at %s", dbPath)
	return nil
}
