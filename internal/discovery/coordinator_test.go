package discovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRefreshCoordinatorSerializesAndReportsResult(t *testing.T) {
	release := make(chan struct{})
	calls := make(chan struct{}, 2)
	coordinator := NewRefreshCoordinator(context.Background(), func(context.Context) (RefreshResult, error) {
		calls <- struct{}{}
		<-release
		return RefreshResult{Fetched: 9, Accepted: 3, Rejected: 6}, nil
	})

	if _, started := coordinator.Trigger("manual"); !started {
		t.Fatal("first refresh did not start")
	}
	<-calls
	if status, started := coordinator.Trigger("periodic"); started || !status.Running {
		t.Fatalf("overlapping refresh was not suppressed: %+v", status)
	}
	close(release)

	deadline := time.Now().Add(time.Second)
	for coordinator.Status().Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := coordinator.Status()
	if status.Running || status.LastResult.Accepted != 3 || status.Source != "manual" || status.LastError != "" {
		t.Fatalf("unexpected completed status: %+v", status)
	}
}

func TestRefreshCoordinatorReportsFailure(t *testing.T) {
	coordinator := NewRefreshCoordinator(context.Background(), func(context.Context) (RefreshResult, error) {
		return RefreshResult{Fetched: 2}, errors.New("provider unavailable")
	})
	coordinator.Trigger("manual")
	deadline := time.Now().Add(time.Second)
	for coordinator.Status().Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := coordinator.Status().LastError; got != "provider unavailable" {
		t.Fatalf("unexpected error: %q", got)
	}
}
