package scheduler

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NaNA1337/super-proxy/internal/benchmark"
	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/health"
	"github.com/NaNA1337/super-proxy/internal/metrics"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/routing"
	"github.com/NaNA1337/super-proxy/internal/xray"
)

const drainingTimeout = 30 * time.Second

type Scheduler struct {
	MaxActive              int
	MaxStandby             int
	RepEngine              *reputation.Engine
	RegionConfig           config.RegionConfig
	ActiveSlots            map[int]*openvpn.Tunnel
	DrainingSlots          map[int]*openvpn.Tunnel // Tunnels being drained before shutdown
	drainingTableIDs       map[int]int
	drainingTunIPs         map[int]string
	StandbyNodes           []*openvpn.Tunnel
	Slots                  *SlotManager
	ManualOverride         map[int]bool
	XraySupervisor         *xray.Supervisor
	Benchmarker            func(ctx context.Context, interfaceName string, mark int) (*models.PerformanceMetrics, error)
	ScoringEngine          *ScoringEngine
	SetupDrainingRoutingFn func(drainingTableID int, interfaceName string, tunIP string) error
	Mu                     sync.Mutex
	ctx                    context.Context
	cancel                 context.CancelFunc
	wg                     sync.WaitGroup
	standbySlotCount       atomic.Int64 // Monotonically increasing counter for standby virtual slots
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
		Benchmarker: func(ctx context.Context, dev string, mark int) (*models.PerformanceMetrics, error) {
			cfg := benchmark.DefaultBenchmarkConfig()
			cfg.RoutingMark = mark
			return benchmark.BenchmarkInterfaceWithConfig(ctx, dev, cfg)
		},
		ScoringEngine:          NewScoringEngine(config.ScoringConfig{}),
		SetupDrainingRoutingFn: routing.SetupDrainingRouting,
		ctx:                    ctx,
		cancel:                 cancel,
	}
	// Start virtual slot counter after active + standby range
	s.standbySlotCount.Store(int64(maxActive + maxStandby + 10))
	return s
}

// Context binds long-lived tunnels to daemon shutdown, not qualification deadlines.
func (s *Scheduler) Context() context.Context { return s.ctx }

// NextTunnelID gives each new tunnel its own interface even while an old slot drains.
func (s *Scheduler) NextTunnelID() int { return int(s.standbySlotCount.Add(1)) }

// DrainSlotLocked is for controllers that already hold Mu.
func (s *Scheduler) DrainSlotLocked(slot int, tunnel *openvpn.Tunnel) {
	s.transitionToDrainingLocked(slot, tunnel)
}

// DrainReplacedTunnelLocked preserves an old tunnel after its slot has already
// been redirected to a verified replacement. It must not remove the replacement
// from ActiveSlots or disable the Xray slot. The caller must hold Mu.
func (s *Scheduler) DrainReplacedTunnelLocked(slot int, tunnel *openvpn.Tunnel) error {
	if tunnel == nil {
		return nil
	}
	if _, exists := s.DrainingSlots[slot]; exists {
		return fmt.Errorf("slot %d already has a draining tunnel", slot)
	}

	drainingTableID := 200 + slot
	tunIP, _ := routing.GetInterfaceIP(tunnel.Interface)
	setupFn := s.SetupDrainingRoutingFn
	if setupFn == nil {
		setupFn = routing.SetupDrainingRouting
	}
	if err := setupFn(drainingTableID, tunnel.Interface, tunIP); err != nil {
		return fmt.Errorf("setup replacement draining route: %w", err)
	}

	tunnel.Mu.Lock()
	tunnel.State = string(SlotDraining)
	tunnel.DrainingStartedAt = time.Now()
	tunnel.Mu.Unlock()
	s.drainingTableIDs[slot] = drainingTableID
	s.drainingTunIPs[slot] = tunIP
	s.DrainingSlots[slot] = tunnel
	if database.DB != nil && tunnel.Node != nil {
		_ = TransitionNode(database.DB, tunnel.Node, models.StatusDraining)
	}

	if sc, _ := s.Slots.GetSlot(slot); sc != nil {
		sc.Mu.Lock()
		sc.DrainingTunnel = tunnel
		sc.DrainingTableID = drainingTableID
		sc.Mu.Unlock()
	}
	log.Printf("[Scheduler] Replaced tunnel on slot %d is DRAINING (dev %s, tunIP %s, table %d); replacement remains active",
		slot, tunnel.Interface, tunIP, drainingTableID)
	return nil
}

// SetXraySupervisor connects the Xray supervisor to dynamically coordinate active egress slots.
func (s *Scheduler) SetXraySupervisor(xsup *xray.Supervisor) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.XraySupervisor = xsup
}

// SetSpeedTestConfig configures the scheduler's benchmarker with custom SpeedTestConfig endpoints and timeouts.
func (s *Scheduler) SetSpeedTestConfig(cfg config.SpeedTestConfig) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	if !cfg.Enabled {
		log.Println("[Scheduler] SpeedTest disabled in config; using lightweight RTT probe")
		s.Benchmarker = func(ctx context.Context, dev string, mark int) (*models.PerformanceMetrics, error) {
			return benchmark.BenchmarkInterfaceWithConfig(ctx, dev, benchmark.BenchmarkConfig{
				RoutingMark:  mark,
				RTTTargetURL: cfg.RTTTargetURL,
				Timeout:      time.Duration(cfg.TimeoutSec) * time.Second,
			})
		}
		return
	}

	benchCfg := benchmark.DefaultBenchmarkConfig()
	if cfg.RTTTargetURL != "" {
		benchCfg.RTTTargetURL = cfg.RTTTargetURL
	}
	if cfg.DownloadURL != "" {
		benchCfg.DownloadURL = cfg.DownloadURL
	}
	if cfg.UploadURL != "" {
		benchCfg.UploadURL = cfg.UploadURL
	}
	if cfg.TimeoutSec > 0 {
		benchCfg.Timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}

	s.Benchmarker = func(ctx context.Context, dev string, mark int) (*models.PerformanceMetrics, error) {
		current := benchCfg
		current.RoutingMark = mark
		return benchmark.BenchmarkInterfaceWithConfig(ctx, dev, current)
	}
	log.Printf("[Scheduler] SpeedTestConfig integrated: RTT=%s, DL=%s, UL=%s, Timeout=%v",
		benchCfg.RTTTargetURL, benchCfg.DownloadURL, benchCfg.UploadURL, benchCfg.Timeout)
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

				// Atomic Xray activation: if Xray activation fails, roll back routing and do NOT commit slot!
				if s.XraySupervisor != nil {
					if err := s.XraySupervisor.ActivateSlot(i); err != nil {
						log.Printf("[Scheduler] ERROR: Failed to activate Xray slot %d: %v. Rolling back promotion.", i, err)
						metrics.XrayErrors.Inc()
						_ = routing.ClearSlotRouting(i)
						newTunnel.Stop()
						continue
					}
				}

				_ = TransitionNode(database.DB, newTunnel.Node, models.StatusActive)
				s.ActiveSlots[i] = newTunnel

				sc, _ := s.Slots.GetSlot(i)
				if sc != nil {
					sc.Mu.Lock()
					sc.ActiveTunnel = newTunnel
					sc.State = SlotActive
					sc.OutboundActive = true
					sc.Mu.Unlock()
				}
			} else {
				log.Printf("[Scheduler] Slot %d is empty, but no standby available.", i)
			}
		}
	}

	// Synchronize Xray active slots to match currently active live slots
	if s.XraySupervisor != nil {
		activeSlots := []int{}
		for i := 0; i < s.MaxActive; i++ {
			if t, ok := s.ActiveSlots[i]; ok && t != nil {
				t.Mu.Lock()
				st := t.State
				t.Mu.Unlock()
				if st == string(SlotActive) {
					select {
					case <-t.Done():
					default:
						activeSlots = append(activeSlots, i)
					}
				}
			}
		}
		if err := s.XraySupervisor.SyncActiveSlots(activeSlots); err != nil {
			log.Printf("[Scheduler] ERROR: Failed to sync Xray active slots to %v: %v", activeSlots, err)
			metrics.XrayErrors.Inc()
			metrics.XraySyncErrors.Inc()
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
	// 1. Immediately request Xray to exclude slot from active routing and verify runtime read-back
	if s.XraySupervisor != nil {
		if err := s.XraySupervisor.DrainingSlot(slot); err != nil {
			log.Printf("[Scheduler] ERROR: Failed to drain Xray slot %d: %v. Aborting draining transition to maintain consistency.", slot, err)
			metrics.XrayErrors.Inc()
			metrics.DrainFailures.Inc()
			// INVARIANT: Do NOT enter DRAINING, do NOT modify Linux draining routes, do NOT remove from ActiveSlots.
			return
		}
	}

	// 2. Only after Xray drain succeeds: mark tunnel state = SlotDraining
	tunnel.Mu.Lock()
	tunnel.State = string(SlotDraining)
	tunnel.DrainingStartedAt = time.Now()
	tunnel.Mu.Unlock()

	// 3. Isolate existing connections into dedicated Draining Table (200 + slot)
	drainingTableID := 200 + slot
	tunIP, _ := routing.GetInterfaceIP(tunnel.Interface)
	setupFn := s.SetupDrainingRoutingFn
	if setupFn == nil {
		setupFn = routing.SetupDrainingRouting
	}
	if err := setupFn(drainingTableID, tunnel.Interface, tunIP); err != nil {
		log.Printf("[Scheduler] CRITICAL: failed to setup draining routing for slot %d: %v. Rolling back Xray drain to prevent connection death.", slot, err)
		metrics.DrainFailures.Inc()

		// Rollback Xray drain to re-include slot in active outbound routing
		if s.XraySupervisor != nil {
			if rbErr := s.XraySupervisor.ActivateSlot(slot); rbErr != nil {
				log.Printf("[Scheduler] CRITICAL: failed to rollback Xray ActivateSlot for slot %d: %v", slot, rbErr)
				metrics.XrayErrors.Inc()
			}
		}

		// Rollback tunnel memory state
		tunnel.Mu.Lock()
		tunnel.State = string(SlotActive)
		tunnel.DrainingStartedAt = time.Time{}
		tunnel.Mu.Unlock()

		// Slot remains ACTIVE in scheduler
		return
	}

	s.drainingTableIDs[slot] = drainingTableID
	s.drainingTunIPs[slot] = tunIP

	// 4. FSM state transition
	_ = TransitionNode(database.DB, tunnel.Node, models.StatusDraining)

	// 5. Move from active to draining map
	delete(s.ActiveSlots, slot)
	s.DrainingSlots[slot] = tunnel

	sc, _ := s.Slots.GetSlot(slot)
	if sc != nil {
		sc.Mu.Lock()
		sc.ActiveTunnel = nil
		sc.DrainingTunnel = tunnel
		sc.DrainingTableID = drainingTableID
		sc.State = SlotDraining
		sc.OutboundActive = false
		sc.Mu.Unlock()
	}

	log.Printf("[Scheduler] Slot %d moved to DRAINING state (dev %s, tunIP %s, table %d, Xray outbound disabled)",
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
			if _, active := s.ActiveSlots[slot]; !active {
				routing.ClearSlotRouting(slot)
			}
			tunnel.Stop()
			s.markNodeFailed(tunnel.Node)
			delete(s.DrainingSlots, slot)
			delete(s.drainingTableIDs, slot)
			delete(s.drainingTunIPs, slot)
			continue
		}

		// Check remaining connections by mark and tunIP
		count, err := GetActiveConnectionCount(slot, tunIP)
		if err != nil || count == ConnectionCountUnknown {
			log.Printf("[Scheduler] Warning: conntrack unavailable for slot %d (%v); keeping tunnel draining until timeout (elapsed: %.1fs)",
				slot, err, elapsed.Seconds())
			continue // DO NOT kill the tunnel prematurely on conntrack failure
		}

		if count > 0 {
			log.Printf("[Scheduler] %s (elapsed: %.1fs)", FormatDrainingStatus(slot, count), elapsed.Seconds())
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

	// Select best candidate node obeying strict Primary/Fallback threshold policy
	selection, err := s.SelectNextCandidate()
	if err != nil || selection == nil || selection.Node == nil {
		return // No qualified candidates available
	}
	node := *selection.Node

	log.Printf("[Scheduler] Evaluating node %s (%s, score=%d, fallback=%v) for standby pool",
		node.IP, node.Country, node.Score, selection.IsFallbackNode)

	// Windowed Prefix Intelligence check (multi-window statistical profile 24h/7d/30d/90d)
	_, prefixPenalty, prefixReason := reputation.EvaluatePrefixRisk(database.DB, node.IP, 0)

	// Reputation Check
	if s.RepEngine != nil {
		res, repErr := s.RepEngine.EvaluateIP(s.ctx, node.IP)
		if repErr != nil {
			log.Printf("[Scheduler] Reputation check returned error for %s: %v", node.IP, repErr)
			if s.RepEngine.FailurePolicy() == "conservative" {
				log.Printf("[Scheduler] Candidate %s REJECTED: reputation query error (%v) under conservative fail-closed policy", node.IP, repErr)
				_ = TransitionNode(database.DB, &node, models.StatusFailed)
				return
			}
		}

		isConservativeUnknown := s.RepEngine.FailurePolicy() == "conservative" && (res == nil || res.Status == reputation.StatusUnknown)
		if (res != nil && res.HardReject) || isConservativeUnknown {
			_ = reputation.RecordPrefixSample(database.DB, node.IP, node.Score, true, true)
			statusStr := "UNKNOWN"
			hardReject := false
			reason := ""
			if res != nil {
				statusStr = string(res.Status)
				hardReject = res.HardReject
				reason = res.ProviderReason
			}
			log.Printf("[Scheduler] Candidate %s REJECTED by reputation policy (Status=%s, HardReject=%v): %s",
				node.IP, statusStr, hardReject, reason)
			_ = TransitionNode(database.DB, &node, models.StatusFailed)
			return
		}

		if res != nil {
			_ = reputation.RecordPrefixSample(database.DB, node.IP, node.Score, res.ScorePenalty > 0, false)
			node.Reputation.FraudScore = res.ScorePenalty
			node.Reputation.Status = string(res.Status)
			node.Reputation.ProviderName = res.ProviderReason
			node.NetClass = res.NetworkInfo
		}
	}

	// Evaluate candidate using unified ScoringEngine
	if s.ScoringEngine != nil {
		scoringRes := s.ScoringEngine.EvaluateNode(&node, !selection.IsFallbackNode, prefixPenalty, prefixReason)
		log.Printf("[Scheduler] %s", scoringRes.Explanation)
		if !scoringRes.Allowed {
			log.Printf("[Scheduler] Candidate %s REJECTED by scoring engine: final score %d", node.IP, scoringRes.FinalScore)
			_ = TransitionNode(database.DB, &node, models.StatusFailed)
			return
		}
		node.Score = scoringRes.FinalScore
	}

	// Persist reputation & network intelligence to DB
	if database.DB != nil {
		database.DB.Model(&node).Updates(map[string]interface{}{
			"score":             node.Score,
			"rep_status":        node.Reputation.Status,
			"rep_fraud_score":   node.Reputation.FraudScore,
			"rep_provider_name": node.Reputation.ProviderName,
			"net_asn":           node.NetClass.ASN,
			"net_isp":           node.NetClass.ISP,
			"net_organization":  node.NetClass.Organization,
			"net_network_type":  node.NetClass.NetworkType,
			"net_is_vpn":        node.NetClass.IsVPN,
			"net_is_proxy":      node.NetClass.IsProxy,
			"net_is_tor":        node.NetClass.IsTor,
			"net_is_hosting":    node.NetClass.IsHosting,
		})
	}

	if err := TransitionNode(database.DB, &node, models.StatusReputationChecked); err != nil {
		log.Printf("[Scheduler] FSM transition error: %v", err)
		return
	}

	// 1. CONNECTING
	if err := TransitionNode(database.DB, &node, models.StatusConnecting); err != nil {
		log.Printf("[Scheduler] FSM connecting error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	tunnel, err := openvpn.StartTunnel(s.ctx, standbyVirtualSlot, &node)
	if err != nil {
		_ = TransitionNode(database.DB, &node, models.StatusFailed)
		return
	}

	time.Sleep(5 * time.Second)

	// 2. HEALTH_CHECK
	if err := TransitionNode(database.DB, &node, models.StatusHealthCheck); err != nil {
		log.Printf("[Scheduler] FSM health check error: %v", err)
	}

	// Verify the tunnel without polluting main route table
	_ = routing.SetupSlotRouting(standbyVirtualSlot, tunnel.Interface)
	node.ObservedExitIP = "" // Establish a fresh baseline for this new tunnel.
	hRes := health.VerifyTunnel(ctx, standbyVirtualSlot, tunnel.Interface, routing.BaseTableID+standbyVirtualSlot, &node)

	if !hRes.TunnelHealthy || hRes.Error != nil {
		log.Printf("[Scheduler] Tunnel %s qualification failed: %v", tunnel.Interface, hRes.Error)
		_ = routing.ClearSlotRouting(standbyVirtualSlot)
		tunnel.Stop()
		_ = TransitionNode(database.DB, &node, models.StatusFailed)
		return
	}

	node.ObservedExitIP = hRes.ObservedExitIP
	database.DB.Model(&node).Update("observed_exit_ip", node.ObservedExitIP)
	log.Printf("[Scheduler] Verified tunnel %s: endpoint=%s, observed exit=%s", tunnel.Interface, node.IP, node.ObservedExitIP)

	// 3. SPEED_TEST
	if err := TransitionNode(database.DB, &node, models.StatusSpeedTest); err != nil {
		log.Printf("[Scheduler] FSM speed test error: %v", err)
	}

	benchFn := s.Benchmarker
	if benchFn != nil {
		benchCtx, benchCancel := context.WithTimeout(s.ctx, 20*time.Second)
		perf, err := benchFn(benchCtx, tunnel.Interface, routing.BaseTableID+standbyVirtualSlot)
		benchCancel()

		_ = routing.ClearSlotRouting(standbyVirtualSlot) // Remove temp routing

		if err != nil || perf == nil {
			log.Printf("[Scheduler] Speed test failed for node %s on %s: %v", node.IP, tunnel.Interface, err)
			tunnel.Stop()
			_ = TransitionNode(database.DB, &node, models.StatusFailed)
			return
		}

		node.Performance = *perf
		if database.DB != nil {
			database.DB.Model(&node).Updates(map[string]interface{}{
				"perf_rtt":                perf.RTT,
				"perf_throughput":         perf.Throughput,
				"perf_download_speed":     perf.DownloadSpeed,
				"perf_upload_speed":       perf.UploadSpeed,
				"perf_upload_status":      perf.UploadStatus,
				"perf_speed_status":       perf.SpeedStatus,
				"perf_packet_loss_status": perf.PacketLossStatus,
				"perf_packet_loss":        perf.PacketLoss,
				"perf_duration_ms":        perf.DurationMs,
				"perf_last_checked":       perf.LastChecked,
			})
		}
	} else {
		_ = routing.ClearSlotRouting(standbyVirtualSlot)
	}

	// 4. QUALIFIED
	if err := TransitionNode(database.DB, &node, models.StatusQualified); err != nil {
		log.Printf("[Scheduler] FSM qualified error: %v", err)
	}

	// 5. STANDBY
	if err := TransitionNode(database.DB, &node, models.StatusStandby); err != nil {
		log.Printf("[Scheduler] FSM standby error: %v", err)
	}

	tunnel.Mu.Lock()
	tunnel.State = string(SlotActive) // The process itself is active
	tunnel.Mu.Unlock()

	s.Mu.Lock()
	s.StandbyNodes = append(s.StandbyNodes, tunnel)
	s.Mu.Unlock()
	log.Printf("[Scheduler] Successfully added tunnel %s to warm standby pool (Node %s: CONNECTING -> HEALTH_CHECK -> SPEED_TEST -> QUALIFIED -> STANDBY).",
		tunnel.Interface, node.IP)
}
