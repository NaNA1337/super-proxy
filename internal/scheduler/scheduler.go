package scheduler

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/health"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/routing"
)

const drainingTimeout = 30 * time.Second

type Scheduler struct {
	MaxActive        int
	MaxStandby       int
	RepEngine        *reputation.Engine
	RegionConfig     config.RegionConfig
	ActiveSlots      map[int]*openvpn.Tunnel
	DrainingSlots    map[int]*openvpn.Tunnel // Tunnels being drained before shutdown
	StandbyNodes     []*openvpn.Tunnel
	ManualOverride   map[int]bool
	Mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	standbySlotCount atomic.Int64 // Monotonically increasing counter for standby virtual slots
}

func NewScheduler(maxActive, maxStandby int, repEngine *reputation.Engine, regionCfg config.RegionConfig) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Scheduler{
		MaxActive:      maxActive,
		MaxStandby:     maxStandby,
		RepEngine:      repEngine,
		RegionConfig:   regionCfg,
		ActiveSlots:    make(map[int]*openvpn.Tunnel),
		DrainingSlots:  make(map[int]*openvpn.Tunnel),
		ManualOverride: make(map[int]bool),
		ctx:            ctx,
		cancel:         cancel,
	}
	// Start virtual slot counter after active + standby range
	s.standbySlotCount.Store(int64(maxActive + maxStandby + 10))
	return s
}

func (s *Scheduler) Start() {
	log.Println("[Scheduler] Starting background scheduler...")
	go s.monitorLoop()
}

func (s *Scheduler) Stop() {
	log.Println("[Scheduler] Stopping scheduler...")
	s.cancel()
}

func (s *Scheduler) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	staleTicker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	defer staleTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			s.Mu.Lock()
			for slot, t := range s.ActiveSlots {
				routing.ClearSlotRouting(slot)
				t.Stop()
			}
			for slot, t := range s.DrainingSlots {
				routing.ClearSlotRouting(slot)
				t.Stop()
			}
			for _, t := range s.StandbyNodes {
				t.Stop()
			}
			s.Mu.Unlock()
			return
		case <-ticker.C:
			s.reconcileActiveSlots()
			s.cleanupDrainingSlots()
			s.maintainStandbyPool()
		case <-staleTicker.C:
			s.cleanStaleNodes()
		}
	}
}

func (s *Scheduler) cleanStaleNodes() {
	// P1-3: Mark nodes unseen for 24 hours as STALE
	database.DB.Model(&models.Node{}).
		Where("last_seen < ? AND status != ?", time.Now().Add(-24*time.Hour), models.StatusStale).
		Update("status", models.StatusStale)
}

func (s *Scheduler) reconcileActiveSlots() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	// 1. Check health of active slots
	for slot, tunnel := range s.ActiveSlots {
		if s.ManualOverride[slot] {
			continue
		}

		// Check if the tunnel process is still alive
		tunnel.Mu.Lock()
		state := tunnel.State
		tunnel.Mu.Unlock()

		if state != string(SlotActive) {
			log.Printf("[Scheduler] Slot %d tunnel %s is dead (State: %s). Transitioning to DRAINING.", slot, tunnel.Node.IP, state)
			s.transitionToDraining(slot, tunnel)
			continue
		}

		ctxTimeout, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		res := health.VerifyTunnel(ctxTimeout, slot, tunnel.Interface, routing.BaseTableID+slot, tunnel.Node)
		cancel()

		if !res.TunnelHealthy || res.Error != nil {
			log.Printf("[Scheduler] Slot %d health check failed (Healthy=%v, Err=%v). Transitioning to DRAINING.", slot, res.TunnelHealthy, res.Error)
			s.transitionToDraining(slot, tunnel)
		}
	}

	// 2. Fill empty active slots from standby pool (P1-2: True Warm Standby)
	for i := 0; i < s.MaxActive; i++ {
		if s.ManualOverride[i] {
			continue
		}

		_, exists := s.ActiveSlots[i]
		if !exists {
			if len(s.StandbyNodes) > 0 {
				newTunnel := s.StandbyNodes[0]
				s.StandbyNodes = s.StandbyNodes[1:]

				// Verify standby tunnel is still alive before promoting
				newTunnel.Mu.Lock()
				standbyState := newTunnel.State
				newTunnel.Mu.Unlock()

				if standbyState != string(SlotActive) {
					log.Printf("[Scheduler] Standby tunnel %s is dead (State: %s), skipping.", newTunnel.Interface, standbyState)
					newTunnel.Stop()
					continue
				}

				log.Printf("[Scheduler] Promoting standby tunnel (%s) to active slot %d", newTunnel.Interface, i)

				// Re-assign the slot index for routing purposes but DON'T restart OpenVPN
				newTunnel.SlotIndex = i

				// Ensure route table for the slot routes via this tunnel's interface
				routing.SetupSlotRouting(i, newTunnel.Interface)

				database.DB.Model(newTunnel.Node).Update("status", models.StatusActive)
				s.ActiveSlots[i] = newTunnel
			} else {
				log.Printf("[Scheduler] Slot %d is empty, but no standby available.", i)
			}
		}
	}
}

// transitionToDraining moves a tunnel from active to draining state.
// Must be called with s.Mu held.
func (s *Scheduler) transitionToDraining(slot int, tunnel *openvpn.Tunnel) {
	tunnel.Mu.Lock()
	tunnel.State = string(SlotDraining)
	tunnel.DrainingStartedAt = time.Now()
	tunnel.Mu.Unlock()

	// Update DB status
	database.DB.Model(tunnel.Node).Updates(map[string]interface{}{
		"status":     models.StatusDraining,
		"fail_count": tunnel.Node.FailCount + 1,
	})

	// Move from active to draining
	delete(s.ActiveSlots, slot)
	s.DrainingSlots[slot] = tunnel
	log.Printf("[Scheduler] Slot %d moved to DRAINING state", slot)
}

// cleanupDrainingSlots checks draining slots and removes them when done.
func (s *Scheduler) cleanupDrainingSlots() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	for slot, tunnel := range s.DrainingSlots {
		// Check timeout first
		tunnel.Mu.Lock()
		elapsed := time.Since(tunnel.DrainingStartedAt)
		tunnel.Mu.Unlock()

		if elapsed > drainingTimeout {
			log.Printf("[Scheduler] Slot %d draining timeout exceeded (%.0fs). Force stopping.", slot, elapsed.Seconds())
			routing.ClearSlotRouting(slot)
			tunnel.Stop()
			s.markNodeFailed(tunnel.Node)
			delete(s.DrainingSlots, slot)
			continue
		}

		// Check remaining connections
		count, err := GetActiveConnectionCount(slot)
		if err != nil {
			log.Printf("[Scheduler] Warning: Failed to check connections for slot %d: %v", slot, err)
			count = 0 // Fallback to safe kill if conntrack is entirely broken
		}

		if count > 0 {
			log.Printf("[Scheduler] %s", FormatDrainingStatus(slot, count))
			continue // Keep draining
		}

		log.Printf("[Scheduler] Slot %d has 0 connections. Draining complete, stopping tunnel.", slot)
		routing.ClearSlotRouting(slot)
		tunnel.Stop()
		s.markNodeFailed(tunnel.Node)
		delete(s.DrainingSlots, slot)
	}
}

// markNodeFailed updates a node's status to FAILED or DEAD based on fail count.
func (s *Scheduler) markNodeFailed(node *models.Node) {
	newStatus := models.StatusFailed
	newFailCount := node.FailCount + 1

	// After 3 failures, mark as DEAD
	if newFailCount >= 3 {
		newStatus = models.StatusDead
		log.Printf("[Scheduler] Node %s has failed %d times, marking as DEAD", node.IP, newFailCount)
	}

	database.DB.Model(node).Updates(map[string]interface{}{
		"status":     newStatus,
		"fail_count": newFailCount,
	})
}

func (s *Scheduler) maintainStandbyPool() {
	s.Mu.Lock()
	standbyCount := len(s.StandbyNodes)
	s.Mu.Unlock()

	if standbyCount >= s.MaxStandby {
		return
	}

	// Use monotonically increasing counter for standby virtual slot IDs to avoid collisions
	standbyVirtualSlot := int(s.standbySlotCount.Add(1))

	// Build region filter for DB query
	allowedCountries := []string{s.RegionConfig.Primary}
	allowedCountries = append(allowedCountries, s.RegionConfig.Fallback...)

	var node models.Node
	// P1-1: Strict Lifecycle + Region filter
	query := database.DB.Where("status = ?", models.StatusDiscovered)
	if len(allowedCountries) > 0 && allowedCountries[0] != "" {
		query = query.Where("country IN ?", allowedCountries)
	}
	// Exclude nodes that have failed too many times
	query = query.Where("fail_count < ?", 3)
	result := query.Order("score DESC").First(&node)
	if result.Error != nil {
		return // No nodes available
	}

	log.Printf("[Scheduler] Evaluating node %s (%s) for standby pool", node.IP, node.Country)

	// P1-4: Reputation Check
	res, _ := s.RepEngine.EvaluateIP(s.ctx, node.IP)
	if res.HardReject {
		database.DB.Model(&node).Update("status", models.StatusFailed)
		return
	}
	database.DB.Model(&node).Update("status", models.StatusReputationChecked)

	// Connect
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	tunnel, err := openvpn.StartTunnel(ctx, standbyVirtualSlot, &node)
	if err != nil {
		database.DB.Model(&node).Updates(map[string]interface{}{
			"status":     models.StatusFailed,
			"fail_count": node.FailCount + 1,
		})
		return
	}

	time.Sleep(5 * time.Second)

	// To verify the tunnel without polluting main route table, we temporarily assign it to its virtual table
	routing.SetupSlotRouting(standbyVirtualSlot, tunnel.Interface)
	hRes := health.VerifyTunnel(ctx, standbyVirtualSlot, tunnel.Interface, routing.BaseTableID+standbyVirtualSlot, &node)
	routing.ClearSlotRouting(standbyVirtualSlot) // Remove temp routing

	if !hRes.TunnelHealthy || hRes.Error != nil {
		tunnel.Stop()
		database.DB.Model(&node).Updates(map[string]interface{}{
			"status":     models.StatusFailed,
			"fail_count": node.FailCount + 1,
		})
		return
	}

	// P1-1: Qualified and Standby
	database.DB.Model(&node).Update("status", models.StatusStandby)
	tunnel.Mu.Lock()
	tunnel.State = string(SlotActive) // The process itself is active
	tunnel.Mu.Unlock()

	s.Mu.Lock()
	s.StandbyNodes = append(s.StandbyNodes, tunnel)
	s.Mu.Unlock()
	log.Printf("[Scheduler] Successfully added tunnel %s to warm standby pool.", tunnel.Interface)
}
