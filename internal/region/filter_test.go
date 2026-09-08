package region

import (
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
)

func TestFilterNodes(t *testing.T) {
	nodes := []models.Node{
		{IP: "1.1.1.1", Country: "JP"},
		{IP: "1.1.1.2", Country: "JP"},
		{IP: "2.2.2.1", Country: "KR"},
		{IP: "3.3.3.1", Country: "US"},
	}

	cfg := config.RegionConfig{
		Primary:  "JP",
		Fallback: []string{"KR", "SG"},
	}

	// Test 1: Minimum required is met by primary (e.g. min = 1, we have 2 JP)
	filtered1 := FilterNodes(nodes, cfg, 1)
	if len(filtered1) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(filtered1))
	}
	for _, n := range filtered1 {
		if n.Country != "JP" {
			t.Errorf("Expected only JP nodes, got %s", n.Country)
		}
	}

	// Test 2: Minimum required NOT met by primary (e.g. min = 3, we have 2 JP, so fallback KR is included)
	filtered2 := FilterNodes(nodes, cfg, 3)
	if len(filtered2) != 3 {
		t.Errorf("Expected 3 nodes (2 JP + 1 KR), got %d", len(filtered2))
	}
	foundKR := false
	for _, n := range filtered2 {
		if n.Country == "KR" {
			foundKR = true
		}
	}
	if !foundKR {
		t.Errorf("Expected to find fallback KR node")
	}

	// Test 3: Unmatched nodes (US) are always excluded
	for _, n := range filtered2 {
		if n.Country == "US" {
			t.Errorf("US node should be excluded entirely")
		}
	}
}
