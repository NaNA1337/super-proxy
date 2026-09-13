package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/discovery"
)

func TestDiscoveryRefreshAPIStartsAndReportsRunningJob(t *testing.T) {
	release := make(chan struct{})
	coordinator := discovery.NewRefreshCoordinator(context.Background(), func(context.Context) (discovery.RefreshResult, error) {
		<-release
		return discovery.RefreshResult{Fetched: 12, Accepted: 4, Rejected: 8}, nil
	})
	SetDiscoveryCoordinator(coordinator)
	defer SetDiscoveryCoordinator(nil)

	rr := httptest.NewRecorder()
	handleDiscoveryRefresh(rr, httptest.NewRequest(http.MethodPost, "/api/v1/discovery/refresh", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		Started bool                    `json:"started"`
		Status  discovery.RefreshStatus `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Started || !response.Status.Running || response.Status.Source != "manual" {
		t.Fatalf("unexpected response: %+v", response)
	}

	rr = httptest.NewRecorder()
	handleDiscoveryRefresh(rr, httptest.NewRequest(http.MethodPost, "/api/v1/discovery/refresh", nil))
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Started {
		t.Fatal("overlapping manual refresh was started")
	}
	close(release)
}
