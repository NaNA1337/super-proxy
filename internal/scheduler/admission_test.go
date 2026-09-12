package scheduler

import (
	"context"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

type admissionTestProvider struct {
	result *reputation.ReputationResult
}

func (p *admissionTestProvider) Name() string    { return "admission-test" }
func (p *admissionTestProvider) IsHealthy() bool { return true }
func (p *admissionTestProvider) CheckIP(context.Context, string) (*reputation.ReputationResult, error) {
	return p.result, nil
}

func TestAdmissionHardRejectsEveryProhibitedNetworkTrait(t *testing.T) {
	cases := []struct {
		name string
		info models.NetworkClass
	}{
		{name: "hosting", info: models.NetworkClass{IsHosting: true}},
		{name: "vpn", info: models.NetworkClass{IsVPN: true}},
		{name: "proxy", info: models.NetworkClass{IsProxy: true}},
		{name: "tor", info: models.NetworkClass{IsTor: true}},
	}

	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := reputation.NewEngineWithConfig(reputation.EngineConfig{FailurePolicy: "conservative"})
			engine.AddProvider(&admissionTestProvider{result: &reputation.ReputationResult{
				Provider:    "admission-test",
				Status:      reputation.StatusRisky,
				NetworkInfo: tc.info,
			}})
			s := NewScheduler(3, 2, engine, config.RegionConfig{Primary: "JP"})
			ip := "198.51.100." + string(rune('1'+index))
			if _, err := s.EvaluateIPAdmission(context.Background(), ip); err == nil {
				t.Fatalf("%s trait must be hard rejected", tc.name)
			}
		})
	}
}

func TestAdmissionRejectsUnknownUnderConservativePolicy(t *testing.T) {
	engine := reputation.NewEngineWithConfig(reputation.EngineConfig{FailurePolicy: "conservative"})
	engine.AddProvider(&admissionTestProvider{result: &reputation.ReputationResult{
		Provider: "admission-test",
		Status:   reputation.StatusUnknown,
	}})
	s := NewScheduler(3, 2, engine, config.RegionConfig{Primary: "JP"})
	if _, err := s.EvaluateIPAdmission(context.Background(), "198.51.100.9"); err == nil {
		t.Fatal("UNKNOWN result must fail closed under conservative policy")
	}
}

func TestAdmissionRejectsProviderCountryMismatch(t *testing.T) {
	engine := reputation.NewEngine()
	engine.AddProvider(&admissionTestProvider{result: &reputation.ReputationResult{
		Provider: "admission-test", Status: reputation.StatusGood, CountryCode: "JP",
		ProviderReason: "clean JP address",
	}})
	s := NewScheduler(3, 2, engine, config.RegionConfig{Primary: "KR"})
	if _, err := s.EvaluateIPAdmissionForRegion(context.Background(), "198.51.100.10", "KR"); err == nil {
		t.Fatal("expected KR candidate with JP provider geolocation to be rejected")
	}
}
