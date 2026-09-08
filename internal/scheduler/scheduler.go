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
	MaxActive    int
	MaxStandby   int
	RepEngine    *reputation.Engine
	ActiveSlots  map[int]*openvpn.Tunnel
	StandbyNodes []*openvpn.Tunnel
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewScheduler(maxActive, maxStandby int, repEngine *reputation.Engine) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		MaxActive:   maxActive,
		MaxStandby:  maxStandby,
		RepEngine:   repEngine,
		ActiveSlots: make(map[int]*openvpn.Tunnel),
		ctx:         ctx,
		cancel:      cancel,
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
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Cleanup all tunnels
			s.mu.Lock()
			for slot, t := range s.ActiveSlots {
				routing.ClearSlotRouting(slot)
				t.Stop()
			}
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.reconcile()
		}
	}
}

func (s *Scheduler) reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Check health of active slots
	for slot, tunnel := range s.ActiveSlots {
		if !tunnel.IsActive {
			log.Printf("[Scheduler] Slot %d tunnel %s is dead (process exited). Removing.", slot, tunnel.Node.IP)
			routing.ClearSlotRouting(slot)
			tunnel.Stop()
			delete(s.ActiveSlots, slot)
			continue
		}

		ctxTimeout, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		ok, _, err := health.CheckTunnelConnectivity(ctxTimeout, tunnel.Interface, "http://1.1.1.1")
		cancel()

		if !ok || err != nil {
			log.Printf("[Scheduler] Slot %d health check failed: %v. Marking dead.", slot, err)
			routing.ClearSlotRouting(slot)
			tunnel.Stop()
			delete(s.ActiveSlots, slot)
		}
	}

	// 2. Fill empty active slots from standby pool
	for i := 0; i < s.MaxActive; i++ {
		if _, ok := s.ActiveSlots[i]; !ok {
			if len(s.StandbyNodes) > 0 {
				log.Printf("[Scheduler] Promoting standby tunnel to slot %d", i)
				newTunnel := s.StandbyNodes[0]
				s.StandbyNodes = s.StandbyNodes[1:]
				
				// Re-assign slot index
				newTunnel.SlotIndex = i
				// Because the tunnel interface might change, for simplicity in Phase 6 we assume
				// the standby tunnel was started with the correct interface OR we restart it.
				// Since tunX is tied to slot index, we MUST restart the OpenVPN process for the correct slot.
				newTunnel.Stop()
				
				log.Printf("[Scheduler] Starting new OpenVPN for slot %d with node %s", i, newTunnel.Node.IP)
				startedTunnel, err := openvpn.StartTunnel(s.ctx, i, newTunnel.Node)
				if err != nil {
					log.Printf("[Scheduler] Failed to start tunnel for slot %d: %v", i, err)
					continue
				}
				
				// Wait and apply routing
				time.Sleep(5 * time.Second)
				routing.SetupSlotRouting(i, startedTunnel.Interface)
				s.ActiveSlots[i] = startedTunnel
			} else {
				// No standby available, try to spawn directly from DB
				s.spawnNewActive(i)
			}
		}
	}
}

func (s *Scheduler) spawnNewActive(slot int) {
	// Find a node from DB
	var node models.Node
	result := database.DB.Where("status = ?", "DISCOVERED").Order("score DESC").First(&node)
	if result.Error != nil {
		log.Printf("[Scheduler] No nodes available in DB to spawn slot %d", slot)
		return
	}

	// Reputation check
	res, _ := s.RepEngine.EvaluateIP(s.ctx, node.IP)
	if res.HardReject {
		log.Printf("[Scheduler] Node %s rejected by reputation engine. Marking FAILED.", node.IP)
		database.DB.Model(&node).Update("status", "FAILED")
		return
	}

	log.Printf("[Scheduler] Spawning new active tunnel for slot %d with node %s", slot, node.IP)
	tunnel, err := openvpn.StartTunnel(s.ctx, slot, &node)
	if err != nil {
		log.Printf("[Scheduler] Failed to start tunnel for slot %d: %v", slot, err)
		database.DB.Model(&node).Update("status", "FAILED")
		return
	}
	
	database.DB.Model(&node).Update("status", "ACTIVE")

	// Wait and apply routing
	go func() {
		time.Sleep(5 * time.Second)
		routing.SetupSlotRouting(slot, tunnel.Interface)
	}()

	s.ActiveSlots[slot] = tunnel
}
