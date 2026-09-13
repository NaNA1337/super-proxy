package discovery

import (
	"context"
	"sync"
	"time"
)

type RefreshResult struct {
	Fetched  int `json:"fetched"`
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

type RefreshStatus struct {
	Running       bool          `json:"running"`
	Source        string        `json:"source,omitempty"`
	LastStarted   time.Time     `json:"last_started,omitempty"`
	LastCompleted time.Time     `json:"last_completed,omitempty"`
	LastError     string        `json:"last_error,omitempty"`
	LastResult    RefreshResult `json:"last_result"`
}

type RefreshFunc func(context.Context) (RefreshResult, error)

// RefreshCoordinator serializes startup, periodic and manual discovery runs.
// A slow provider can therefore never create overlapping quota-consuming scans.
type RefreshCoordinator struct {
	ctx     context.Context
	refresh RefreshFunc
	mu      sync.RWMutex
	status  RefreshStatus
}

func NewRefreshCoordinator(ctx context.Context, refresh RefreshFunc) *RefreshCoordinator {
	return &RefreshCoordinator{ctx: ctx, refresh: refresh}
}

// Trigger starts a refresh in the background. started is false when an existing
// refresh is still running; callers can safely poll Status in either case.
func (c *RefreshCoordinator) Trigger(source string) (status RefreshStatus, started bool) {
	if c == nil || c.refresh == nil {
		return RefreshStatus{LastError: "discovery refresh is unavailable"}, false
	}
	c.mu.Lock()
	if c.status.Running {
		status = c.status
		c.mu.Unlock()
		return status, false
	}
	c.status.Running = true
	c.status.Source = source
	c.status.LastStarted = time.Now().UTC()
	c.status.LastError = ""
	status = c.status
	c.mu.Unlock()

	go func() {
		result, err := c.refresh(c.ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.Running = false
		c.status.LastCompleted = time.Now().UTC()
		c.status.LastResult = result
		if err != nil {
			c.status.LastError = err.Error()
		}
	}()
	return status, true
}

func (c *RefreshCoordinator) Status() RefreshStatus {
	if c == nil {
		return RefreshStatus{LastError: "discovery refresh is unavailable"}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}
