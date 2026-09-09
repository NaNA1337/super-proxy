package reputation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type mockProvider struct {
	name       string
	healthy    bool
	result     *Result
	err        error
	callCount  int
}

func (m *mockProvider) Name() string    { return m.name }
func (m *mockProvider) IsHealthy() bool { return m.healthy }
func (m *mockProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
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

func TestReputation_TimeoutNeverEqualsGoodOrBad(t *testing.T) {
	engine := NewEngine()
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
		t.Fatalf("Expected StatusUnknown on provider timeout, got %s", res.Status)
	}
	if res.HardReject {
		t.Fatalf("Provider timeout must never cause HardReject")
	}
}

func TestReputation_HardRejectPreserved(t *testing.T) {
	engine := NewEngine()
	engine.AddProvider(&mockProvider{
		name:    "MaliciousDetector",
		healthy: true,
		result: &Result{
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

func TestReputation_PrefixIntelligence_Threshold(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open sqlite memory DB: %v", err)
	}
	_ = db.AutoMigrate(&models.PrefixIntelligence{})

	ip1 := "192.0.2.10"
	ip2 := "192.0.2.20"
	ip3 := "192.0.2.30"

	// 1 bad sample: should NOT condemn the entire /24
	_ = RecordPrefixSample(db, ip1, 50, true, false)
	isHighRisk, penalty, _ := EvaluatePrefixRisk(db, ip1, 3)
	if isHighRisk || penalty > 0 {
		t.Fatalf("Single bad sample should NOT flag prefix as high risk (got penalty %d)", penalty)
	}

	// 2nd bad sample: still below threshold of 3
	_ = RecordPrefixSample(db, ip2, 40, true, false)
	isHighRisk, penalty, _ = EvaluatePrefixRisk(db, ip2, 3)
	if isHighRisk || penalty > 0 {
		t.Fatalf("2 bad samples should still be below threshold 3")
	}

	// 3rd bad sample: reaches threshold, triggers prefix penalty
	_ = RecordPrefixSample(db, ip3, 30, true, false)
	isHighRisk, penalty, exp := EvaluatePrefixRisk(db, ip3, 3)
	if !isHighRisk || penalty == 0 {
		t.Fatalf("3 bad samples MUST trigger prefix penalty, got risk=%v, penalty=%d, exp=%s", isHighRisk, penalty, exp)
	}
}

func TestReputation_NetworkIntelligence_SoftPenaltyNotHardReject(t *testing.T) {
	engine := NewEngine()
	engine.AddProvider(&mockProvider{
		name:    "IPInfoMock",
		healthy: true,
		result: &Result{
			IP:     "198.51.100.4",
			Status: StatusGood,
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
	if res.HardReject {
		t.Fatalf("Hosting/VPN must NEVER trigger HardReject")
	}
	if !res.NetworkInfo.IsHosting || !res.NetworkInfo.IsVPN {
		t.Fatalf("Expected NetworkInfo to reflect Hosting and VPN")
	}
}
