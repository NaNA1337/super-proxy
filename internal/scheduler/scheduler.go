package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/health"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/routing"
)

type Scheduler struct {
	MaxActive      int
	MaxStandby     int
	RepEngine      *reputation.Engine
	ActiveSlots    map[int]*openvpn.Tunnel
	StandbyNodes   []*openvpn.Tunnel
	ManualOverride map[int]bool
	Mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
}

func NewScheduler(maxActive, maxStandby int, repEngine *reputation.Engine) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		MaxActive:      maxActive,
		MaxStandby:     maxStandby,
		RepEngine:      repEngine,
		ActiveSlots:    make(map[int]*openvpn.Tunnel),
		ManualOverride: make(map[int]bool),
		ctx:            ctx,
		cancel:         cancel,
	}
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
			for _, t := range s.StandbyNodes {
				t.Stop()
			}
			s.Mu.Unlock()
			return
		case <-ticker.C:
			s.reconcileActiveSlots()
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
		if tunnel.State != string(SlotActive) {
			if tunnel.State == string(SlotDraining) {
				// TODO: P2 Connection Tracking check, for now simple timeout
				log.Printf("[Scheduler] Slot %d is draining, forcing kill.", slot)
			} else {
				log.Printf("[Scheduler] Slot %d tunnel %s is dead (State: %s). Removing.", slot, tunnel.Node.IP, tunnel.State)
			}
			routing.ClearSlotRouting(slot)
			tunnel.Stop()
			delete(s.ActiveSlots, slot)
			continue
		}

		ctxTimeout, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		res := health.VerifyTunnel(ctxTimeout, slot, tunnel.Interface, routing.BaseTableID+slot, tunnel.Node)
		cancel()

		if !res.TunnelHealthy || res.Error != nil {
			log.Printf("[Scheduler] Slot %d health check failed (Healthy=%v, Err=%v). Marking dead.", slot, res.TunnelHealthy, res.Error)
			routing.ClearSlotRouting(slot)
			tunnel.Stop()
			delete(s.ActiveSlots, slot)
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

func (s *Scheduler) maintainStandbyPool() {
	s.Mu.Lock()
	standbyCount := len(s.StandbyNodes)
	s.Mu.Unlock()

	if standbyCount >= s.MaxStandby {
		return
	}

	// Calculate a virtual slot index for standby interfaces (e.g. 100, 101...) to avoid collision
	standbyVirtualSlot := s.MaxActive + standbyCount

	var node models.Node
	// P1-1: Strict Lifecycle
	result := database.DB.Where("status = ?", models.StatusDiscovered).Order("score DESC").First(&node)
	if result.Error != nil {
		return // No nodes available
	}

	log.Printf("[Scheduler] Evaluating node %s for standby pool", node.IP)

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
		database.DB.Model(&node).Update("status", models.StatusFailed)
		return
	}

	time.Sleep(5 * time.Second)

	// To verify the tunnel without polluting main route table, we temporarily assign it to its virtual table
	routing.SetupSlotRouting(standbyVirtualSlot, tunnel.Interface)
	hRes := health.VerifyTunnel(ctx, standbyVirtualSlot, tunnel.Interface, routing.BaseTableID+standbyVirtualSlot, &node)
	routing.ClearSlotRouting(standbyVirtualSlot) // Remove temp routing

	if !hRes.TunnelHealthy || hRes.Error != nil {
		tunnel.Stop()
		database.DB.Model(&node).Update("status", models.StatusFailed)
		return
	}

	// P1-1: Qualified and Standby
	database.DB.Model(&node).Update("status", models.StatusStandby)
	tunnel.State = string(SlotActive) // The process itself is active
	
	s.Mu.Lock()
	s.StandbyNodes = append(s.StandbyNodes, tunnel)
	s.Mu.Unlock()
	log.Printf("[Scheduler] Successfully added tunnel %s to warm standby pool.", tunnel.Interface)
}
