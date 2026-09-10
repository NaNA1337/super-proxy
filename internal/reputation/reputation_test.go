package reputation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type mockProvider struct {
	name      string
	healthy   bool
	result    *ReputationResult
	err       error
	callCount int
}

func (m *mockProvider) Name() string    { return m.name }
func (m *mockProvider) IsHealthy() bool { return m.healthy }
func (m *mockProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestReputation_CacheTTLAndHits(t *testing.T) {
	cache := NewCache(1 * time.Hour)
	ip := "198.51.100.1"
	res := &Result{
		IP:           ip,
		Status:       StatusGood,
		ScorePenalty: 0,
	}

	_, hit := cache.Get(ip)
	if hit {
		t.Fatalf("Expected cache miss for fresh IP")
	}

	cache.Set(ip, res)

	cached, hit := cache.Get(ip)
	if !hit || cached == nil || cached.Status != StatusGood {
		t.Fatalf("Expected cache hit for %s", ip)
	}

	hits, misses, requests := cache.Stats()
	if hits != 1 || misses != 1 || requests != 2 {
		t.Fatalf("Unexpected cache stats: hits=%d, misses=%d, requests=%d", hits, misses, requests)
	}
}

func TestReputation_ConservativeUnknownFailClosed(t *testing.T) {
	engine := NewEngineWithConfig(EngineConfig{
		FailurePolicy: "conservative",
	})
	engine.AddProvider(&mockProvider{
		name:    "FailingProvider",
		healthy: true,
		err:     errors.New("connection timeout to provider API"),
	})

	res, err := engine.EvaluateIP(context.Background(), "198.51.100.2")
	if err != nil {
		t.Fatalf("Engine should not fail outright on provider error: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Fatalf("Expected StatusUnknown on provider error under conservative policy, got %s", res.Status)
	}
	if res.HardReject {
		t.Fatalf("Provider timeout must not cause HardReject")
	}
}

func TestReputation_LenientPolicyAppliesPenalty(t *testing.T) {
	engine := NewEngineWithConfig(EngineConfig{
		FailurePolicy:  "lenient",
		LenientPenalty: 25,
	})
	engine.AddProvider(&mockProvider{
		name:    "TimeoutProvider",
		healthy: true,
		err:     errors.New("429 rate limit"),
	})

	res, err := engine.EvaluateIP(context.Background(), "198.51.100.2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if res.ScorePenalty < 25 {
		t.Errorf("Expected lenient penalty >= 25, got %d", res.ScorePenalty)
	}
}

func TestReputation_HardRejectPreserved(t *testing.T) {
	engine := NewEngine()
	engine.AddProvider(&mockProvider{
		name:    "MaliciousDetector",
		healthy: true,
		result: &ReputationResult{
			Provider:       "MaliciousDetector",
			IP:             "198.51.100.3",
			Status:         StatusBad,
			HardReject:     true,
			ProviderReason: "Confirmed C2 Botnet",
		},
	})

	res, err := engine.EvaluateIP(context.Background(), "198.51.100.3")
	if err != nil {
		t.Fatalf("EvaluateIP error: %v", err)
	}
	if !res.HardReject || res.Status != StatusBad {
		t.Fatalf("Expected HardReject with StatusBad, got HardReject=%v, Status=%s", res.HardReject, res.Status)
	}
}

func TestReputation_DatabaseEvidencePersistence(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	_ = db.AutoMigrate(&models.ReputationEvidence{}, &models.NetworkIntelligence{}, &models.ASNObservation{})

	engine := NewEngine()
	engine.SetDB(db)
	conf := 85.0
	reports := 42
	engine.AddProvider(&mockProvider{
		name:    "AbuseIPDB",
		healthy: true,
		result: &ReputationResult{
			Provider:        "AbuseIPDB",
			IP:              "203.0.113.5",
			Status:          StatusBad,
			AbuseConfidence: &conf,
			Reports:         &reports,
			ASN:             "AS13335",
			ISP:             "Cloudflare",
			ObservedAt:      time.Now(),
		},
	})

	res, err := engine.EvaluateIP(context.Background(), "203.0.113.5")
	if err != nil {
		t.Fatalf("EvaluateIP error: %v", err)
	}
	if len(res.Evidences) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(res.Evidences))
	}

	var savedEv models.ReputationEvidence
	if err := db.Where("ip = ?", "203.0.113.5").First(&savedEv).Error; err != nil {
		t.Fatalf("failed to find persisted evidence: %v", err)
	}
	if savedEv.Provider != "AbuseIPDB" || savedEv.AbuseConfidence != 85 || savedEv.Reports != 42 {
		t.Errorf("persisted evidence mismatch: %+v", savedEv)
	}

	var netIntel models.NetworkIntelligence
	if err := db.Where("ip = ?", "203.0.113.5").First(&netIntel).Error; err != nil {
		t.Fatalf("failed to find persisted network intelligence: %v", err)
	}
	if netIntel.ASN != "AS13335" || netIntel.ISP != "Cloudflare" {
		t.Errorf("persisted network intelligence mismatch: %+v", netIntel)
	}
}

func TestReputation_PrefixIntelligence_AbolishNaive3BadRule(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open sqlite memory DB: %v", err)
	}
	_ = db.AutoMigrate(&models.PrefixObservation{}, &models.PrefixIntelligence{})

	prefix := "198.51.100.0/24"

	// Scenario A: 3 bad out of 2000 total samples -> bad ratio is 0.15% -> MUST NOT condemn /24!
	for i := 1; i <= 2000; i++ {
		isBad := i <= 3 // only 3 bad IPs
		obs := models.PrefixObservation{
			Prefix:     prefix,
			IP:         fmt.Sprintf("198.51.100.%d", (i%250)+1),
			IsBad:      isBad,
			ObservedAt: time.Now(),
		}
		_ = db.Create(&obs).Error
	}

	isHighRisk, penalty, exp := EvaluatePrefixRisk(db, "198.51.100.50", 3)
	if isHighRisk || penalty > 0 {
		t.Fatalf("3 bad samples out of 2000 MUST NOT be marked high risk (got risk=%v, penalty=%d, exp=%s)",
			isHighRisk, penalty, exp)
	}

	// Scenario B: 3 bad out of 3 total samples (100% bad ratio) -> SHOULD be flagged
	dbB, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	_ = dbB.AutoMigrate(&models.PrefixObservation{}, &models.PrefixIntelligence{})

	for i := 1; i <= 3; i++ {
		obs := models.PrefixObservation{
			Prefix:       prefix,
			IP:           fmt.Sprintf("198.51.100.%d", i),
			IsBad:        true,
			IsHardReject: true,
			ObservedAt:   time.Now(),
		}
		_ = dbB.Create(&obs).Error
	}

	// In Scenario B, with 3/3 hard rejects, soft penalty or risk is applied
	_, penaltyB, _ := EvaluatePrefixRisk(dbB, "198.51.100.1", 3)
	if penaltyB <= 0 {
		t.Fatalf("3/3 bad samples should have penalty > 0, got %d", penaltyB)
	}
}

func TestReputation_ASNProfiling(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite memory DB: %v", err)
	}
	_ = db.AutoMigrate(&models.ASNObservation{})

	asn := "AS64496"
	// Insert 10 samples: 8 bad, 2 good
	for i := 1; i <= 10; i++ {
		obs := models.ASNObservation{
			ASN:          asn,
			ISP:          "Example ISP",
			IP:           fmt.Sprintf("198.51.100.%d", i),
			IsBad:        i <= 8,
			IsHardReject: i <= 5,
			Score:        70,
			ObservedAt:   time.Now().Add(-1 * time.Hour),
		}
		_ = db.Create(&obs).Error
	}

	profile, err := QueryASNProfile(context.Background(), db, asn, Window24h)
	if err != nil {
		t.Fatalf("QueryASNProfile error: %v", err)
	}
	if profile.SampleCount != 10 {
		t.Errorf("expected 10 samples, got %d", profile.SampleCount)
	}
	if profile.BadCount != 8 {
		t.Errorf("expected 8 bad, got %d", profile.BadCount)
	}
	if profile.RiskLevel != "CRITICAL" {
		t.Errorf("expected CRITICAL risk level for 80%% bad ratio, got %s", profile.RiskLevel)
	}
	if profile.ScorePenalty <= 0 {
		t.Errorf("expected score penalty > 0 for critical ASN risk, got %d", profile.ScorePenalty)
	}
}

func TestReputation_NetworkIntelligence_SoftPenaltyNotHardReject(t *testing.T) {
	engine := NewEngine()
	engine.AddProvider(&mockProvider{
		name:    "IPInfoMock",
		healthy: true,
		result: &ReputationResult{
			Provider: "IPInfoMock",
			IP:       "198.51.100.4",
			Status:   StatusGood,
			NetworkInfo: models.NetworkClass{
				ISP:         "DigitalOcean",
				NetworkType: "hosting",
				IsHosting:   true,
				IsVPN:       true,
			},
		},
	})

	res, err := engine.EvaluateIP(context.Background(), "198.51.100.4")
	if err != nil {
		t.Fatalf("EvaluateIP error: %v", err)
	}
	if res.Status == StatusBad {
		t.Fatalf("Hosting/VPN must NEVER result in StatusBad, expected StatusRisky, got %s", res.Status)
	}
	if res.Status != StatusRisky {
		t.Fatalf("Expected StatusRisky for Hosting/VPN traits, got %s", res.Status)
	}
}

func TestReputation_VPNIsNotBad(t *testing.T) {
	engine := NewEngine()
	engine.AddProvider(&mockProvider{
		name:    "VPNProvider",
		healthy: true,
		result: &ReputationResult{
			Provider:     "VPNProvider",
			IP:           "198.51.100.9",
			Status:       StatusRisky,
			ScorePenalty: 15,
			NetworkInfo: models.NetworkClass{
				IsVPN:       true,
				NetworkType: "vpn",
			},
		},
	})

	res, err := engine.EvaluateIP(context.Background(), "198.51.100.9")
	if err != nil {
		t.Fatalf("EvaluateIP error: %v", err)
	}
	if res.Status == StatusBad {
		t.Fatalf("VPN != malicious: node with VPN trait must NOT be marked BAD (got StatusBad)")
	}
	if res.Status != StatusRisky {
		t.Fatalf("Expected StatusRisky for VPN trait, got %s", res.Status)
	}
	if res.ScorePenalty != 15 {
		t.Errorf("Expected ScorePenalty 15, got %d", res.ScorePenalty)
	}
}

func TestReputation_MaliciousEvidenceIsBad(t *testing.T) {
	engine := NewEngine()
	engine.AddProvider(&mockProvider{
		name:    "AbuseMock",
		healthy: true,
		result: &ReputationResult{
			Provider:   "AbuseMock",
			IP:         "198.51.100.10",
			Status:     StatusBad,
			HardReject: true,
		},
	})

	res, err := engine.EvaluateIP(context.Background(), "198.51.100.10")
	if err != nil {
		t.Fatalf("EvaluateIP error: %v", err)
	}
	if res.Status != StatusBad {
		t.Fatalf("Expected StatusBad for confirmed malicious evidence, got %s", res.Status)
	}
	if !res.HardReject {
		t.Fatalf("Expected HardReject = true for confirmed malicious evidence")
	}
}

func TestReputation_SmallSampleProtectionAnd90dWindow(t *testing.T) {
	// 1. Test small sample protection: 2 samples, 2 bad.
	// Must NOT declare isHighRisk=true, must only apply soft penalty.
	dbSmall, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite DB: %v", err)
	}
	_ = dbSmall.AutoMigrate(&models.PrefixObservation{}, &models.PrefixIntelligence{})

	prefix := "192.0.2.0/24"
	for i := 1; i <= 2; i++ {
		obs := models.PrefixObservation{
			Prefix:       prefix,
			IP:           fmt.Sprintf("192.0.2.%d", i),
			IsBad:        true,
			IsHardReject: true,
			ObservedAt:   time.Now().Add(-1 * time.Hour),
		}
		_ = dbSmall.Create(&obs).Error
	}

	isHighRisk, penalty, exp := EvaluatePrefixRisk(dbSmall, "192.0.2.1", 3)
	if isHighRisk {
		t.Fatalf("Small sample (2/2 bad) must NOT be marked isHighRisk=true (got risk=%v, penalty=%d, exp=%s)",
			isHighRisk, penalty, exp)
	}
	if penalty <= 0 {
		t.Fatalf("Small sample (2/2 bad) should have soft penalty > 0, got %d", penalty)
	}

	// 2. Test 90d window chronic abuse:
	// Insert observations 60 days ago (outside 30d, but within 90d)
	db90d, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	_ = db90d.AutoMigrate(&models.PrefixObservation{}, &models.PrefixIntelligence{})

	prefixChronic := "203.0.113.0/24"
	for i := 1; i <= 15; i++ {
		obs := models.PrefixObservation{
			Prefix:       prefixChronic,
			IP:           fmt.Sprintf("203.0.113.%d", i),
			IsBad:        true,
			IsHardReject: true,
			ObservedAt:   time.Now().Add(-60 * 24 * time.Hour), // 60 days ago
		}
		_ = db90d.Create(&obs).Error
	}

	isHighRisk90, penalty90, exp90 := EvaluatePrefixRisk(db90d, "203.0.113.1", 0)
	if !isHighRisk90 || penalty90 < 25 {
		t.Fatalf("Chronic 90d abuse must be detected as high risk: got risk=%v, penalty=%d, exp=%s",
			isHighRisk90, penalty90, exp90)
	}

	// 3. Test RDAP Provider boundary: unmeasured densities are -1.0
	rdapProv := NewExternalRDAPPrefixProvider("")
	require.Equal(t, "ExternalRDAPPrefixProvider", rdapProv.Name())
}

