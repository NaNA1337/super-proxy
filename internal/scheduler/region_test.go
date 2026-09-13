package scheduler

import (
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) {
	discovery.ClearOVPNSecretCache()
	t.Cleanup(discovery.ClearOVPNSecretCache)
	var err error
	database.DB, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open memory db: %v", err)
	}
	if err := database.DB.AutoMigrate(&models.Node{}); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}
}

func cacheAllTestNodeCredentials(t *testing.T) {
	var nodes []models.Node
	if err := database.DB.Find(&nodes).Error; err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		discovery.SetOVPNSecret(nodes[i].ID, "test-credential")
	}
}

func TestPrimaryPreferred(t *testing.T) {
	setupTestDB(t)

	// Seed 5 Primary qualified nodes (JP)
	for i := 1; i <= 5; i++ {
		database.DB.Create(&models.Node{
			ID:       string(rune('A' + i)),
			IP:       "192.0.2." + string(rune('0'+i)),
			Country:  "JP",
			Score:    100 + i,
			Status:   models.StatusQualified,
			LastSeen: time.Now(),
		})
	}

	// Seed 2 Fallback nodes (US) with higher scores
	database.DB.Create(&models.Node{
		ID:       "US-1",
		IP:       "198.51.100.1",
		Country:  "US",
		Score:    9999, // very high score!
		Status:   models.StatusQualified,
		LastSeen: time.Now(),
	})

	cfg := config.RegionConfig{
		Primary:  "JP",
		Fallback: []string{"US", "KR"},
	}
	sched := NewScheduler(3, 2, reputation.NewEngine(), cfg) // required = 3 + 2 = 5
	cacheAllTestNodeCredentials(t)

	res, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatalf("unexpected error selecting candidate: %v", err)
	}

	if res.FallbackEnabled {
		t.Errorf("expected fallback to be DISABLED because primary count (5) >= required (5)")
	}
	if res.IsFallbackNode {
		t.Errorf("expected primary node, got fallback node")
	}
	if res.Node.Country != "JP" {
		t.Errorf("expected selected node country JP, got %s", res.Node.Country)
	}
}

func TestDiscoveredDoesNotCountTowardQualifiedCapacity(t *testing.T) {
	setupTestDB(t)

	// Seed 10 DISCOVERED Primary nodes (JP) - none are qualified yet
	for i := 1; i <= 10; i++ {
		database.DB.Create(&models.Node{
			ID:       string(rune('A' + i)),
			IP:       "192.0.2." + string(rune('0'+i)),
			Country:  "JP",
			Score:    100 + i,
			Status:   models.StatusDiscovered,
			LastSeen: time.Now(),
		})
	}

	cfg := config.RegionConfig{
		Primary:  "JP",
		Fallback: []string{"US"},
	}
	sched := NewScheduler(3, 2, reputation.NewEngine(), cfg) // required = 5
	cacheAllTestNodeCredentials(t)

	if _, err := sched.SelectNextCandidate(); err == nil {
		t.Fatal("DISCOVERED nodes must not be selectable before reputation admission")
	}
}

func TestFallbackOnlyWhenPrimaryInsufficient(t *testing.T) {
	setupTestDB(t)

	// Seed only 2 Primary nodes (JP), but required is 5
	for i := 1; i <= 2; i++ {
		database.DB.Create(&models.Node{
			ID:       "JP-" + string(rune('0'+i)),
			IP:       "192.0.2." + string(rune('0'+i)),
			Country:  "JP",
			Score:    100 + i,
			Status:   models.StatusReputationChecked,
			LastSeen: time.Now(),
		})
	}

	// Seed Fallback nodes (KR)
	database.DB.Create(&models.Node{
		ID:       "KR-1",
		IP:       "203.0.113.1",
		Country:  "KR",
		Score:    500,
		Status:   models.StatusReputationChecked,
		LastSeen: time.Now(),
	})

	cfg := config.RegionConfig{
		Primary:  "JP",
		Fallback: []string{"KR"},
	}
	sched := NewScheduler(3, 2, reputation.NewEngine(), cfg) // required = 5
	cacheAllTestNodeCredentials(t)

	// 1. First selection: Fallback is enabled, but remaining Primary nodes MUST be chosen first!
	res1, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatalf("selection 1 failed: %v", err)
	}
	if !res1.FallbackEnabled {
		t.Errorf("expected fallback to be ENABLED because primary count (2) < required (5)")
	}
	if res1.Node.Country != "JP" {
		t.Errorf("expected remaining primary node JP to be picked first, got %s", res1.Node.Country)
	}

	// Mark the selected JP node as ACTIVE so it's no longer DISCOVERED
	database.DB.Model(&models.Node{}).Where("id = ?", res1.Node.ID).Update("status", models.StatusActive)

	// 2. Second selection: Picks second JP node
	res2, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatalf("selection 2 failed: %v", err)
	}
	if res2.Node.Country != "JP" {
		t.Errorf("expected second JP node, got %s", res2.Node.Country)
	}
	database.DB.Model(&models.Node{}).Where("id = ?", res2.Node.ID).Update("status", models.StatusActive)

	// 3. Third selection: Primary is now completely exhausted! Must now pick Fallback KR node!
	res3, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatalf("selection 3 failed: %v", err)
	}
	if !res3.IsFallbackNode || res3.Node.Country != "KR" {
		t.Errorf("expected fallback node KR, got %s (isFallback=%v)", res3.Node.Country, res3.IsFallbackNode)
	}
}

func TestHighScoreFallbackCannotBypassPrimary(t *testing.T) {
	setupTestDB(t)

	// Primary node with low score
	database.DB.Create(&models.Node{
		ID:       "JP-LOW",
		IP:       "192.0.2.1",
		Country:  "JP",
		Score:    10, // low score
		Status:   models.StatusQualified,
		LastSeen: time.Now(),
	})

	// Fallback node with huge score
	database.DB.Create(&models.Node{
		ID:       "US-HUGE",
		IP:       "198.51.100.99",
		Country:  "US",
		Score:    999999, // huge score
		Status:   models.StatusQualified,
		LastSeen: time.Now(),
	})

	cfg := config.RegionConfig{
		Primary:  "JP",
		Fallback: []string{"US"},
	}
	sched := NewScheduler(1, 0, reputation.NewEngine(), cfg) // required = 1
	cacheAllTestNodeCredentials(t)

	res, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must select JP-LOW, NOT US-HUGE!
	if res.Node.ID != "JP-LOW" {
		t.Errorf("HIGH SCORE FALLBACK BYPASSED PRIMARY! Expected JP-LOW, got %s (country: %s, score: %d)",
			res.Node.ID, res.Node.Country, res.Node.Score)
	}
	if res.FallbackEnabled {
		t.Errorf("fallback should be disabled when primary count (1) >= required (1)")
	}
}

func TestPrimaryQualifiedCapacitySatisfied(t *testing.T) {
	setupTestDB(t)

	// 3 Active JP nodes
	for i := 1; i <= 3; i++ {
		database.DB.Create(&models.Node{
			ID:       string(rune('1' + i)),
			IP:       "192.0.2." + string(rune('0'+i)),
			Country:  "JP",
			Score:    100,
			Status:   models.StatusActive,
			LastSeen: time.Now(),
		})
	}
	// 2 Standby JP nodes
	for i := 4; i <= 5; i++ {
		database.DB.Create(&models.Node{
			ID:       string(rune('1' + i)),
			IP:       "192.0.2." + string(rune('0'+i)),
			Country:  "JP",
			Score:    100,
			Status:   models.StatusStandby,
			LastSeen: time.Now(),
		})
	}
	// 1 Qualified JP candidate node
	database.DB.Create(&models.Node{
		ID:       "JP-QUALIFIED",
		IP:       "192.0.2.200",
		Country:  "JP",
		Score:    50,
		Status:   models.StatusQualified,
		LastSeen: time.Now(),
	})

	// Fallback US node with high score
	database.DB.Create(&models.Node{
		ID:       "US-HUGE",
		IP:       "198.51.100.99",
		Country:  "US",
		Score:    999999,
		Status:   models.StatusReputationChecked,
		LastSeen: time.Now(),
	})

	cfg := config.RegionConfig{
		Primary:  "JP",
		Fallback: []string{"US"},
	}
	sched := NewScheduler(3, 2, reputation.NewEngine(), cfg) // required = 5
	cacheAllTestNodeCredentials(t)

	res, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Total primary qualified capacity is 3(ACTIVE) + 2(STANDBY) + 1(QUALIFIED) = 6 >= 5(required)
	if res.QualifiedCapacity < 5 {
		t.Errorf("expected QualifiedCapacity >= 5, got %d", res.QualifiedCapacity)
	}
	if res.FallbackEnabled {
		t.Errorf("expected Fallback to be DISABLED when Primary qualified capacity meets required")
	}
	if res.Node.ID != "JP-QUALIFIED" {
		t.Errorf("expected JP-QUALIFIED node to be selected, got %s (country: %s)", res.Node.ID, res.Node.Country)
	}
}

func TestCredentiallessQualifiedNodeDoesNotBlockFallback(t *testing.T) {
	setupTestDB(t)
	requireCreate := func(node *models.Node) {
		if err := database.DB.Create(node).Error; err != nil {
			t.Fatal(err)
		}
	}
	requireCreate(&models.Node{ID: "JP-NO-CREDENTIAL", IP: "192.0.2.10", Country: "JP", Status: models.StatusQualified})
	requireCreate(&models.Node{ID: "US-READY", IP: "198.51.100.10", Country: "US", Status: models.StatusReputationChecked})
	discovery.SetOVPNSecret("US-READY", "test-credential")

	sched := NewScheduler(1, 0, reputation.NewEngine(), config.RegionConfig{Primary: "JP", Fallback: []string{"US"}})
	result, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if result.QualifiedCapacity != 0 || !result.FallbackEnabled || result.Node.ID != "US-READY" {
		t.Fatalf("credentialless primary must not block ready fallback: %+v", result)
	}
}

func TestHistoricalFailureCountDoesNotExcludeRediscoveredCandidate(t *testing.T) {
	setupTestDB(t)
	node := models.Node{
		ID: "KR-RETRY", IP: "198.51.100.77", Country: "KR",
		Status: models.StatusReputationChecked, FailCount: 27, Score: 70,
	}
	if err := database.DB.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	discovery.SetOVPNSecret(node.ID, "fresh-credential")

	sched := NewScheduler(3, 0, reputation.NewEngine(), config.RegionConfig{Primary: "KR"})
	result, err := sched.SelectNextCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if result.Node == nil || result.Node.ID != node.ID {
		t.Fatalf("rediscovered node was excluded by diagnostic failure history: %+v", result)
	}
}
