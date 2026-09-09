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
	drainingTableIDs map[int]int
	drainingTunIPs   map[int]string
	StandbyNodes     []*openvpn.Tunnel
	Slots            *SlotManager
	ManualOverride   map[int]bool
	Mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	standbySlotCount atomic.Int64 // Monotonically increasing counter for standby virtual slots
}

func NewScheduler(maxActive, maxStandby int, repEngine *reputation.Engine, regionCfg config.RegionConfig) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Scheduler{
		MaxActive:        maxActive,
		MaxStandby:       maxStandby,
		RepEngine:        repEngine,
		RegionConfig:     regionCfg,
		ActiveSlots:      make(map[int]*openvpn.Tunnel),
		DrainingSlots:    make(map[int]*openvpn.Tunnel),
		drainingTableIDs: make(map[int]int),
		drainingTunIPs:   make(map[int]string),
		Slots:            NewSlotManager(maxActive),
		ManualOverride:   make(map[int]bool),
		ctx:              ctx,
		cancel:           cancel,
	}
	// Start virtual slot counter after active + standby range
	s.standbySlotCount.Store(int64(maxActive + maxStandby + 10))
	return s
}

func (s *Scheduler) Start() {
	log.Println("[Scheduler] Starting background scheduler...")
	s.wg.Add(1)
	go s.monitorLoop()
}

func (s *Scheduler) Stop() {
	log.Println("[Scheduler] Stopping scheduler...")
	s.cancel()
	// Block until monitorLoop and all tunnel cleanup goroutines complete cleanly
	s.wg.Wait()
	log.Println("[Scheduler] Scheduler stopped and all resources cleaned up.")
}

func (s *Scheduler) monitorLoop() {
	defer s.wg.Done()
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
				drainingTableID := s.drainingTableIDs[slot]
				tunIP := s.drainingTunIPs[slot]
				routing.ClearDrainingRouting(drainingTableID, tunIP)
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
	// Mark nodes unseen for 24 hours as STALE
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
			s.transitionToDrainingLocked(slot, tunnel)
			continue
		}

		ctxTimeout, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		res := health.VerifyTunnel(ctxTimeout, slot, tunnel.Interface, routing.BaseTableID+slot, tunnel.Node)
		cancel()

		if !res.TunnelHealthy || res.Error != nil {
			log.Printf("[Scheduler] Slot %d health check failed (Healthy=%v, Err=%v). Transitioning to DRAINING.", slot, res.TunnelHealthy, res.Error)
			s.transitionToDrainingLocked(slot, tunnel)
		}
	}

	// 2. Fill empty active slots from standby pool (True Warm Standby)
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
				if err := routing.SetupSlotRouting(i, newTunnel.Interface); err != nil {
					log.Printf("[Scheduler] Failed to setup slot routing for slot %d: %v", i, err)
					newTunnel.Stop()
					continue
				}

				_ = TransitionNode(database.DB, newTunnel.Node, models.StatusActive)
				s.ActiveSlots[i] = newTunnel

				sc, _ := s.Slots.GetSlot(i)
				if sc != nil {
					sc.Mu.Lock()
					sc.ActiveTunnel = newTunnel
					sc.State = SlotActive
					sc.Mu.Unlock()
				}
			} else {
				log.Printf("[Scheduler] Slot %d is empty, but no standby available.", i)
			}
		}
	}
}

// TransitionToDraining public method allowing manual switch and external controllers to drain a slot safely
func (s *Scheduler) TransitionToDraining(slot int, tunnel *openvpn.Tunnel) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.transitionToDrainingLocked(slot, tunnel)
}

// transitionToDrainingLocked moves a tunnel from active to draining state with isolated routing.
// Must be called with s.Mu held.
func (s *Scheduler) transitionToDrainingLocked(slot int, tunnel *openvpn.Tunnel) {
	tunnel.Mu.Lock()
	tunnel.State = string(SlotDraining)
	tunnel.DrainingStartedAt = time.Now()
	tunnel.Mu.Unlock()

	// 1. Isolate into dedicated Draining Table (200 + slot)
	drainingTableID := 200 + slot
	tunIP, _ := routing.GetInterfaceIP(tunnel.Interface)
	if err := routing.SetupDrainingRouting(drainingTableID, tunnel.Interface, tunIP); err != nil {
		log.Printf("[Scheduler] Warning: failed to setup draining routing for slot %d: %v", slot, err)
	}

	s.drainingTableIDs[slot] = drainingTableID
	s.drainingTunIPs[slot] = tunIP

	// 2. FSM state transition
	_ = TransitionNode(database.DB, tunnel.Node, models.StatusDraining)

	// 3. Move from active to draining map
	delete(s.ActiveSlots, slot)
	s.DrainingSlots[slot] = tunnel

	sc, _ := s.Slots.GetSlot(slot)
	if sc != nil {
		sc.Mu.Lock()
		sc.ActiveTunnel = nil
		sc.DrainingTunnel = tunnel
		sc.DrainingTableID = drainingTableID
		sc.State = SlotDraining
		sc.Mu.Unlock()
	}

	log.Printf("[Scheduler] Slot %d moved to DRAINING state (dev %s, tunIP %s, table %d)",
		slot, tunnel.Interface, tunIP, drainingTableID)
}

// cleanupDrainingSlots checks draining slots and removes them when conntrack count hits 0 or timeout.
func (s *Scheduler) cleanupDrainingSlots() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	for slot, tunnel := range s.DrainingSlots {
		tunnel.Mu.Lock()
		elapsed := time.Since(tunnel.DrainingStartedAt)
		tunnel.Mu.Unlock()

		tunIP := s.drainingTunIPs[slot]
		drainingTableID := s.drainingTableIDs[slot]

		if elapsed > drainingTimeout {
			log.Printf("[Scheduler] Slot %d draining timeout exceeded (%.0fs). Force stopping.", slot, elapsed.Seconds())
			routing.ClearDrainingRouting(drainingTableID, tunIP)
			routing.ClearSlotRouting(slot)
			tunnel.Stop()
			s.markNodeFailed(tunnel.Node)
			delete(s.DrainingSlots, slot)
			delete(s.drainingTableIDs, slot)
			delete(s.drainingTunIPs, slot)
			continue
		}

		// Check remaining connections by mark and tunIP
		count, err := GetActiveConnectionCount(slot, tunIP)
		if err != nil {
			log.Printf("[Scheduler] Warning: Failed to check connections for slot %d: %v", slot, err)
			count = 0 // Fallback to safe kill if conntrack is entirely broken
		}

		if count > 0 {
			log.Printf("[Scheduler] %s", FormatDrainingStatus(slot, count))
			continue // Keep draining
		}

		log.Printf("[Scheduler] Slot %d has 0 connections. Draining complete, stopping tunnel.", slot)
		routing.ClearDrainingRouting(drainingTableID, tunIP)
		tunnel.Stop()
		s.markNodeFailed(tunnel.Node)
		delete(s.DrainingSlots, slot)
		delete(s.drainingTableIDs, slot)
		delete(s.drainingTunIPs, slot)

		sc, _ := s.Slots.GetSlot(slot)
		if sc != nil {
			sc.Mu.Lock()
			sc.DrainingTunnel = nil
			sc.Mu.Unlock()
		}
	}
}

// markNodeFailed updates a node's status to FAILED or DEAD using the FSM.
func (s *Scheduler) markNodeFailed(node *models.Node) {
	_ = TransitionNode(database.DB, node, models.StatusFailed)
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
	// Strict Lifecycle + Region filter
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

	// Reputation Check
	res, _ := s.RepEngine.EvaluateIP(s.ctx, node.IP)
	if res.HardReject {
		_ = TransitionNode(database.DB, &node, models.StatusFailed)
		return
	}

	// Soft penalty persisted to DB
	if res.ScorePenalty > 0 {
		node.Score -= res.ScorePenalty
		database.DB.Model(&node).Update("score", node.Score)
	}
	database.DB.Model(&node).Updates(map[string]interface{}{
		"rep_fraud_score":   res.ScorePenalty,
		"rep_provider_name": res.ProviderReason,
	})

	if err := TransitionNode(database.DB, &node, models.StatusReputationChecked); err != nil {
		log.Printf("[Scheduler] FSM transition error: %v", err)
		return
	}

	// Connect
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	tunnel, err := openvpn.StartTunnel(ctx, standbyVirtualSlot, &node)
	if err != nil {
		_ = TransitionNode(database.DB, &node, models.StatusFailed)
		return
	}

	time.Sleep(5 * time.Second)

	// Verify the tunnel without polluting main route table
	_ = routing.SetupSlotRouting(standbyVirtualSlot, tunnel.Interface)
	hRes := health.VerifyTunnel(ctx, standbyVirtualSlot, tunnel.Interface, routing.BaseTableID+standbyVirtualSlot, &node)
	_ = routing.ClearSlotRouting(standbyVirtualSlot) // Remove temp routing

	if !hRes.TunnelHealthy || hRes.Error != nil {
		tunnel.Stop()
		_ = TransitionNode(database.DB, &node, models.StatusFailed)
		return
	}

	// Transition to QUALIFIED, then to STANDBY
	if err := TransitionNode(database.DB, &node, models.StatusQualified); err != nil {
		log.Printf("[Scheduler] FSM qualified error: %v", err)
	}
	if err := TransitionNode(database.DB, &node, models.StatusStandby); err != nil {
		log.Printf("[Scheduler] FSM standby error: %v", err)
	}

	tunnel.Mu.Lock()
	tunnel.State = string(SlotActive) // The process itself is active
	tunnel.Mu.Unlock()

	s.Mu.Lock()
	s.StandbyNodes = append(s.StandbyNodes, tunnel)
	s.Mu.Unlock()
	log.Printf("[Scheduler] Successfully added tunnel %s to warm standby pool (Node %s: QUALIFIED -> STANDBY).",
		tunnel.Interface, node.IP)
}
