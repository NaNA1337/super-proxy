package agentapi

import (
	"encoding/json"
	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationLookupUsesReturnedIDAndSnapshot(t *testing.T) {
	op := createSwitchOperation("lease-operation-id", 0, "node")
	snapshot, ok := getOperation(op.ID)
	if !ok || snapshot.ID != op.ID {
		t.Fatal("returned ID cannot be polled")
	}
	updateOpStatus(op, OpActive, "")
	if snapshot.Status != OpRequested {
		t.Fatal("operation reader shares mutable state")
	}
	latest, _ := getOperation(op.ID)
	if latest.Status != OpActive {
		t.Fatal("operation status did not advance")
	}
}

func TestEmptyExitsAndRoutingContract(t *testing.T) {
	s := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	SetScheduler(s)
	defer SetScheduler(nil)
	w := httptest.NewRecorder()
	handleCurrentExits(w, httptest.NewRequest("GET", "/api/v1/current-exits", nil))
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty exits: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	handleRoutingOverview(w, httptest.NewRequest("GET", "/api/v1/routing", nil))
	var r struct {
		Slots []struct {
			TableID int `json:"table_id"`
			Fwmark  int `json:"fwmark"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Slots) != 3 || r.Slots[0].TableID != 100 || r.Slots[2].Fwmark != 102 {
		t.Fatalf("incorrect routing contract: %+v", r)
	}
}

func TestSanitizeKeyOnlyQuery(t *testing.T) {
	if strings.Contains(sanitizeURI("/metrics?key=secret"), "secret") {
		t.Fatal("key leaked into log URI")
	}
}

func TestUnauthenticatedRequestsDoNotDrainManagerQuota(t *testing.T) {
	auth := getVisitorLimiter("192.0.2.199", true)
	unauth := getVisitorLimiter("192.0.2.199", false)
	if auth == unauth {
		t.Fatal("rate buckets are shared")
	}
	for i := 0; i < 20; i++ {
		unauth.Allow()
	}
	for i := 0; i < 50; i++ {
		if !auth.Allow() {
			t.Fatal("authenticated burst reduced by unauthenticated requests")
		}
	}
}
