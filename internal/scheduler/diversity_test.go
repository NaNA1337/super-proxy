package scheduler

import (
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

func TestPrefixDiversityRejectsEndpointAndObservedExitCollisions(t *testing.T) {
	s := NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	s.ActiveSlots[0] = &openvpn.Tunnel{Node: &models.Node{
		ID: "active-a", IP: "126.37.15.22", ObservedExitIP: "203.0.113.80",
	}}

	if err := s.CheckPrefixDiversity(&models.Node{ID: "candidate-b", IP: "126.37.15.200"}, "", -1); err == nil {
		t.Fatal("candidate sharing endpoint /24 with active node must be rejected")
	}
	if err := s.CheckPrefixDiversity(&models.Node{ID: "candidate-c", IP: "192.0.2.10"}, "203.0.113.99", -1); err == nil {
		t.Fatal("candidate sharing observed-exit /24 with active node must be rejected")
	}
	if err := s.CheckPrefixDiversity(&models.Node{ID: "candidate-d", IP: "192.0.2.10"}, "198.51.100.4", -1); err != nil {
		t.Fatalf("independent endpoint and exit prefixes must be allowed: %v", err)
	}
}

func TestPrefixDiversityExcludesSlotBeingReplaced(t *testing.T) {
	s := NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	s.ActiveSlots[1] = &openvpn.Tunnel{Node: &models.Node{ID: "old", IP: "126.37.15.22"}}
	if err := s.CheckPrefixDiversity(&models.Node{ID: "replacement", IP: "126.37.15.200"}, "", 1); err != nil {
		t.Fatalf("replacement may reuse the prefix of the slot it replaces: %v", err)
	}
}
