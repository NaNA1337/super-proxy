package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SupervisorState represents the current state of the Xray supervisor.
type SupervisorState string

const (
	StateStopped    SupervisorState = "STOPPED"
	StateStarting   SupervisorState = "STARTING"
	StateRunning    SupervisorState = "RUNNING"
	StateRestarting SupervisorState = "RESTARTING"
)

// Supervisor oversees the Xray process lifecycle, configuration validation,
// health readiness, crash recovery with exponential backoff, and runtime active-set outbound control.
type Supervisor struct {
	configPath string
	apiAddr    string
	socksAddr  string
	xrayBin    string
	slotCount  int

	mu                 sync.RWMutex
	cmd                *exec.Cmd
	state              SupervisorState
	restarts           int
	lastRestart        time.Time
	consecutiveCrashes int
	stopped            bool
	activeOutbounds    map[string]bool
	outboundMarks      map[string]int
	processDone        chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	vlessEnabled       bool
	vlessOnly443       bool

	// Callbacks for metrics and observability
	OnCrash   func(err error)
	OnRestart func(attempt int)
}

func inspectConfigForVless(configPath string) (enabled bool, only443 bool) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, false
	}
	var raw struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
		Routing struct {
			Rules []struct {
				RuleTag string `json:"ruleTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, false
	}
	for _, in := range raw.Inbounds {
		if in.Tag == "vless-in" {
			enabled = true
			break
		}
	}
	for _, r := range raw.Routing.Rules {
		if r.RuleTag == "vless-non-443-block" {
			only443 = true
			break
		}
	}
	return enabled, only443
}

// NewSupervisor creates an instance of Supervisor.
func NewSupervisor(configPath string, apiPort int, socksListen string, socksPort int, slotCount int) *Supervisor {
	if apiPort <= 0 {
		apiPort = 10085
	}
	if socksPort <= 0 {
		socksPort = 1080
	}
	if socksListen == "" {
		socksListen = "127.0.0.1"
	}
	if slotCount <= 0 {
		slotCount = 3
	}

	xrayBin := "xray"
	if customBin := os.Getenv("XRAY_BINARY_PATH"); customBin != "" {
		xrayBin = customBin
	}

	ctx, cancel := context.WithCancel(context.Background())

	activeMap := make(map[string]bool)
	marksMap := make(map[string]int)
	for i := 0; i < slotCount; i++ {
		tag := fmt.Sprintf("exit-%d", i)
		activeMap[tag] = false // Initial state: no slots active until verified by scheduler
		marksMap[tag] = 100 + i // base table
	}

	vlessEnabled, vlessOnly443 := inspectConfigForVless(configPath)

	return &Supervisor{
		configPath:      configPath,
		apiAddr:         fmt.Sprintf("127.0.0.1:%d", apiPort),
		socksAddr:       fmt.Sprintf("%s:%d", socksListen, socksPort),
		xrayBin:         xrayBin,
		slotCount:       slotCount,
		state:           StateStopped,
		activeOutbounds: activeMap,
		outboundMarks:   marksMap,
		vlessEnabled:    vlessEnabled,
		vlessOnly443:    vlessOnly443,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// ValidateConfig executes "xray run -test -config <path>" to strictly verify configuration syntax.
func (s *Supervisor) ValidateConfig(configPath string) error {
	/* #nosec G204 */
	cmd := exec.Command(s.xrayBin, "run", "-test", "-config", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xray configuration validation failed for %s: %w (output: %s)",
			configPath, err, string(out))
	}
	return nil
}

// Start validates the configuration, launches Xray, waits for readiness, and begins monitoring.
func (s *Supervisor) Start() error {
	s.mu.Lock()
	if s.state == StateRunning || s.state == StateStarting {
		s.mu.Unlock()
		return errors.New("supervisor already running or starting")
	}
	s.state = StateStarting
	s.stopped = false
	if !s.vlessEnabled {
		s.vlessEnabled, s.vlessOnly443 = inspectConfigForVless(s.configPath)
	}
	s.mu.Unlock()

	// 1. Validate configuration before launching
	if err := s.ValidateConfig(s.configPath); err != nil {
		s.mu.Lock()
		s.state = StateStopped
		s.mu.Unlock()
		return fmt.Errorf("cannot start xray, config invalid: %w", err)
	}

	// 2. Start process
	if err := s.startProcessLocked(); err != nil {
		s.mu.Lock()
		s.state = StateStopped
		s.mu.Unlock()
		return err
	}

	// 3. Wait for readiness on API and SOCKS ports
	if err := s.waitReady(10 * time.Second); err != nil {
		_ = s.Stop()
		return fmt.Errorf("xray process started but failed readiness check: %w", err)
	}

	s.mu.Lock()
	s.state = StateRunning
	s.mu.Unlock()

	log.Printf("[XraySupervisor] Xray is READY and listening on SOCKS %s, API %s", s.socksAddr, s.apiAddr)

	// 4. Begin crash monitoring loop
	s.wg.Add(1)
	go s.monitorLoop()

	return nil
}

func (s *Supervisor) startProcessLocked() error {
	/* #nosec G204 */
	cmd := exec.Command(s.xrayBin, "run", "-config", s.configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	log.Printf("[XraySupervisor] Launching %s with config %s", s.xrayBin, s.configPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xray process: %w", err)
	}

	s.cmd = cmd
	s.processDone = make(chan struct{})

	// Drain logs asynchronously
	go s.drainPipe("stdout", stdout)
	go s.drainPipe("stderr", stderr)

	return nil
}

func (s *Supervisor) drainPipe(name string, r io.Reader) {
	if r == nil {
		return
	}
	buf := make([]byte, 2048)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// Uncomment for debug if needed:
			// log.Printf("[Xray-%s] %s", name, string(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}

// waitReady polls the API port and SOCKS port until both accept connections or timeout occurs.
func (s *Supervisor) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		apiConn, err1 := net.DialTimeout("tcp", s.apiAddr, 200*time.Millisecond)
		if err1 == nil {
			apiConn.Close()
		}

		socksConn, err2 := net.DialTimeout("tcp", s.socksAddr, 200*time.Millisecond)
		if err2 == nil {
			socksConn.Close()
		}

		if err1 == nil && err2 == nil {
			return nil
		}

		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for xray readiness on API %s and SOCKS %s", s.apiAddr, s.socksAddr)
}

// monitorLoop waits for the Xray process to exit and automatically restarts it with exponential backoff.
func (s *Supervisor) monitorLoop() {
	defer s.wg.Done()

	for {
		s.mu.RLock()
		cmd := s.cmd
		stopped := s.stopped
		doneChan := s.processDone
		s.mu.RUnlock()

		if stopped || cmd == nil {
			return
		}

		// Single owner of cmd.Wait()
		err := cmd.Wait()
		if doneChan != nil {
			close(doneChan)
		}

		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			return
		}

		s.consecutiveCrashes++
		s.restarts++
		s.lastRestart = time.Now()
		s.state = StateRestarting
		crashes := s.consecutiveCrashes
		s.mu.Unlock()

		log.Printf("[XraySupervisor] WARNING: Xray process exited unexpectedly (err: %v). Crash count: %d", err, crashes)
		if s.OnCrash != nil {
			s.OnCrash(err)
		}

		// Exponential backoff: 1s, 2s, 4s, 8s, up to 30s
		backoffSeconds := 1 << (crashes - 1)
		if backoffSeconds > 30 || backoffSeconds <= 0 {
			backoffSeconds = 30
		}
		backoff := time.Duration(backoffSeconds) * time.Second
		log.Printf("[XraySupervisor] Backoff %v before restarting Xray (attempt #%d)...", backoff, crashes)

		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff):
		}

		if s.OnRestart != nil {
			s.OnRestart(crashes)
		}

		// Re-validate and start
		if valErr := s.ValidateConfig(s.configPath); valErr != nil {
			log.Printf("[XraySupervisor] Config validation failed during recovery: %v", valErr)
			continue
		}

		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			return
		}
		if startErr := s.startProcessLocked(); startErr != nil {
			log.Printf("[XraySupervisor] Failed to restart xray: %v", startErr)
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()

		if readyErr := s.waitReady(10 * time.Second); readyErr != nil {
			log.Printf("[XraySupervisor] Restarted xray failed readiness: %v", readyErr)
			_ = s.killCurrentProcess()
			continue
		}

		s.mu.Lock()
		s.state = StateRunning
		s.mu.Unlock()
		log.Printf("[XraySupervisor] Xray successfully recovered and RUNNING.")

		// Start a health timer to reset consecutive crash counter after 5 minutes of stability
		go func(currentAttempt int) {
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(5 * time.Minute):
				s.mu.Lock()
				if s.consecutiveCrashes == currentAttempt && s.state == StateRunning {
					log.Printf("[XraySupervisor] Stable for 5 minutes. Resetting consecutive crash counter to 0.")
					s.consecutiveCrashes = 0
				}
				s.mu.Unlock()
			}
		}(crashes)
	}
}

// SyncActiveSlots synchronizes Xray routing rules to route proxy traffic exclusively
// to the specified active slots via Xray's RoutingService (adrules).
// It does NOT remove outbound handlers (no rmo), guaranteeing existing TCP streams remain alive.
func (s *Supervisor) SyncActiveSlots(activeSlots []int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncActiveSlotsLocked(activeSlots)
}

func (s *Supervisor) generateBalancers() []map[string]interface{} {
	balancers := []map[string]interface{}{
		{
			"tag": "vpn-balancer",
			"selector": []string{
				"exit-",
			},
			"strategy": map[string]interface{}{
				"type": "random",
			},
		},
	}

	var generateSubsets func(start int, cur []int)
	generateSubsets = func(start int, cur []int) {
		if len(cur) >= 2 {
			tagParts := make([]string, len(cur))
			selector := make([]string, len(cur))
			for idx, sl := range cur {
				tagParts[idx] = fmt.Sprintf("%d", sl)
				selector[idx] = fmt.Sprintf("exit-%d", sl)
			}
			balancers = append(balancers, map[string]interface{}{
				"tag":      "balancer-" + strings.Join(tagParts, "-"),
				"selector": selector,
				"strategy": map[string]interface{}{
					"type": "random",
				},
			})
		}
		for i := start; i < s.slotCount; i++ {
			generateSubsets(i+1, append(cur, i))
		}
	}
	generateSubsets(0, []int{})
	return balancers
}

// applyCandidateRoutingLocked applies candidate routing rules to Xray runtime and verifies them.
// It DOES NOT mutate s.activeOutbounds, enabling a clean transactional candidate model.
func (s *Supervisor) applyCandidateRoutingLocked(candidateSlots []int, drainingSlot int) error {
	slotMap := make(map[int]bool)
	for _, sl := range candidateSlots {
		if sl >= 0 && sl < s.slotCount {
			slotMap[sl] = true
		}
	}

	sorted := make([]int, 0, len(slotMap))
	for sl := range slotMap {
		sorted = append(sorted, sl)
	}
	sort.Ints(sorted)

	// Build routing rules replacement
	rules := []map[string]interface{}{
		{
			"type":        "field",
			"inboundTag":  []string{"api"},
			"outboundTag": "api",
		},
	}

	if s.vlessEnabled {
		if len(sorted) == 0 {
			vlessRule := map[string]interface{}{
				"type":        "field",
				"ruleTag":     "active-balancer-rule-vless",
				"inboundTag":  []string{"vless-in"},
				"outboundTag": "block",
			}
			if s.vlessOnly443 {
				vlessRule["port"] = "443"
			}
			rules = append(rules, vlessRule)
		} else if len(sorted) == 1 {
			vlessRule := map[string]interface{}{
				"type":        "field",
				"ruleTag":     "active-balancer-rule-vless",
				"inboundTag":  []string{"vless-in"},
				"outboundTag": fmt.Sprintf("exit-%d", sorted[0]),
			}
			if s.vlessOnly443 {
				vlessRule["port"] = "443"
			}
			rules = append(rules, vlessRule)
		} else {
			tagParts := make([]string, len(sorted))
			for idx, sl := range sorted {
				tagParts[idx] = fmt.Sprintf("%d", sl)
			}
			balancerTag := "balancer-" + strings.Join(tagParts, "-")
			vlessRule := map[string]interface{}{
				"type":        "field",
				"ruleTag":     "active-balancer-rule-vless",
				"inboundTag":  []string{"vless-in"},
				"balancerTag": balancerTag,
			}
			if s.vlessOnly443 {
				vlessRule["port"] = "443"
			}
			rules = append(rules, vlessRule)
		}

		if s.vlessOnly443 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ruleTag":     "vless-non-443-block",
				"inboundTag":  []string{"vless-in"},
				"outboundTag": "block",
			})
		}
	}

	if len(sorted) == 0 {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ruleTag":     "active-balancer-rule",
			"inboundTag":  []string{"proxy"},
			"outboundTag": "block",
		})
	} else if len(sorted) == 1 {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ruleTag":     "active-balancer-rule",
			"inboundTag":  []string{"proxy"},
			"outboundTag": fmt.Sprintf("exit-%d", sorted[0]),
		})
	} else {
		tagParts := make([]string, len(sorted))
		for idx, sl := range sorted {
			tagParts[idx] = fmt.Sprintf("%d", sl)
		}
		balancerTag := "balancer-" + strings.Join(tagParts, "-")
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ruleTag":     "active-balancer-rule",
			"inboundTag":  []string{"proxy"},
			"balancerTag": balancerTag,
		})
	}

	configWrapper := map[string]interface{}{
		"routing": map[string]interface{}{
			"balancers": s.generateBalancers(),
			"rules":     rules,
		},
	}

	tmpFile, err := os.CreateTemp("", "xray_rules_*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp rules json: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if err := json.NewEncoder(tmpFile).Encode(configWrapper); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to encode rules json: %w", err)
	}
	_ = tmpFile.Close()

	/* #nosec G204 */
	cmd := exec.Command(s.xrayBin, "api", "adrules", "--server="+s.apiAddr, tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to sync active slots via xray api adrules: %w (output: %s)", err, string(out))
	}

	// Active-set runtime read-back: verify Xray routing rules actually reflect the candidate active slots
	if err := s.verifyRuntimeRoutingLocked(sorted, drainingSlot); err != nil {
		return fmt.Errorf("runtime read-back verification failed for candidate slots %v: %w", sorted, err)
	}

	return nil
}

func (s *Supervisor) syncActiveSlotsLocked(activeSlots []int) error {
	oldSlots := s.getActiveSlotsLocked()

	// 1. Apply candidate state to runtime
	if err := s.applyCandidateRoutingLocked(activeSlots, -1); err != nil {
		// Rollback runtime to old state if candidate application failed
		if rbErr := s.applyCandidateRoutingLocked(oldSlots, -1); rbErr != nil {
			log.Printf("[XraySupervisor] CRITICAL SAFETY STATE: rollback after sync failure also failed: %v", rbErr)
		}
		return err
	}

	// 2. COMMIT memory state ONLY after runtime application and verification succeed
	slotMap := make(map[int]bool)
	for _, sl := range activeSlots {
		if sl >= 0 && sl < s.slotCount {
			slotMap[sl] = true
		}
	}
	for i := 0; i < s.slotCount; i++ {
		tag := fmt.Sprintf("exit-%d", i)
		s.activeOutbounds[tag] = slotMap[i]
	}

	log.Printf("[XraySupervisor] Active slots TRANSACTION COMMITTED to %v", activeSlots)
	return nil
}

type lsRulesResponse struct {
	Rules []struct {
		RuleTag     string `json:"ruleTag"`
		Tag         string `json:"tag"`
		BalancerTag string `json:"balancerTag"`
	} `json:"rules"`
}

// verifyRuntimeRoutingLocked performs an active-set runtime read-back via Xray API (lsrules and bi)
// to strictly verify that Xray has committed the routing configuration using exact-set comparisons.
func (s *Supervisor) verifyRuntimeRoutingLocked(expectedSlots []int, drainingSlot int) error {
	/* #nosec G204 */
	cmd := exec.Command(s.xrayBin, "api", "lsrules", "--server="+s.apiAddr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("runtime read-back query to xray lsrules failed: %w (output: %s)", err, string(out))
	}

	var lsResp lsRulesResponse
	if parseErr := json.Unmarshal(out, &lsResp); parseErr != nil {
		return fmt.Errorf("failed to parse xray lsrules json output: %w (raw: %s)", parseErr, string(out))
	}

	// 1. Locate active-balancer-rule
	var activeRule *struct {
		RuleTag     string `json:"ruleTag"`
		Tag         string `json:"tag"`
		BalancerTag string `json:"balancerTag"`
	}
	for i := range lsResp.Rules {
		if lsResp.Rules[i].RuleTag == "active-balancer-rule" {
			activeRule = &lsResp.Rules[i]
			break
		}
	}
	if activeRule == nil {
		return fmt.Errorf("runtime read-back mismatch: active-balancer-rule not found in rules: %s", string(out))
	}

	// 2. If a slot is DRAINING, strictly verify it is NOT targeted as the direct outbound tag
	if drainingSlot >= 0 {
		drainingTag := fmt.Sprintf("exit-%d", drainingSlot)
		if activeRule.Tag == drainingTag {
			return fmt.Errorf("CRITICAL VIOLATION: draining slot %s is targeted directly by active-balancer-rule", drainingTag)
		}
	}

	// 3. Exact comparison of the active target
	if len(expectedSlots) == 0 {
		if activeRule.Tag != "block" && activeRule.Tag != "" {
			return fmt.Errorf("runtime read-back mismatch: expected block rule for empty active slots, got tag %s", activeRule.Tag)
		}
	} else if len(expectedSlots) == 1 {
		expectedTag := fmt.Sprintf("exit-%d", expectedSlots[0])
		// Strict exact equality comparison - never substring contains (e.g. exit-1 vs exit-10)
		if activeRule.Tag != expectedTag {
			return fmt.Errorf("runtime read-back mismatch: expected exact single outbound tag %q, got %q", expectedTag, activeRule.Tag)
		}
	} else {
		// Multi-slot: verify balancer and exact selector set
		tagParts := make([]string, len(expectedSlots))
		for idx, sl := range expectedSlots {
			tagParts[idx] = fmt.Sprintf("%d", sl)
		}
		expectedBalancer := "balancer-" + strings.Join(tagParts, "-")

		/* #nosec G204 */
		cmdBi := exec.Command(s.xrayBin, "api", "bi", "--server="+s.apiAddr, expectedBalancer)
		outBi, errBi := cmdBi.CombinedOutput()
		if errBi != nil || !strings.Contains(string(outBi), "Selects:") {
			return fmt.Errorf("runtime read-back mismatch: balancer %s not active via bi: %v (output: %s)", expectedBalancer, errBi, string(outBi))
		}

		// Parse structured selectors from balancer output
		actualSelectors := make(map[string]bool)
		inSelects := false
		for _, line := range strings.Split(string(outBi), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "Selects:") {
				inSelects = true
				continue
			}
			if inSelects {
				if strings.HasPrefix(trimmed, "- ") {
					inSelects = false
					continue
				}
				fields := strings.Fields(trimmed)
				for _, f := range fields {
					if strings.HasPrefix(f, "exit-") {
						actualSelectors[f] = true
					}
				}
			}
		}

		// Strict set comparison: every expected slot must be present
		for _, sl := range expectedSlots {
			expectedTag := fmt.Sprintf("exit-%d", sl)
			if !actualSelectors[expectedTag] {
				return fmt.Errorf("runtime read-back mismatch: expected slot %s not selected by balancer %s (actual: %v)",
					expectedTag, expectedBalancer, actualSelectors)
			}
		}

		// Also strictly verify draining slot is not in the balancer's selector pool
		if drainingSlot >= 0 {
			drainingTag := fmt.Sprintf("exit-%d", drainingSlot)
			if actualSelectors[drainingTag] {
				return fmt.Errorf("CRITICAL VIOLATION: draining slot %s found in active balancer %s: %v",
					drainingTag, expectedBalancer, actualSelectors)
			}
		}

		// Set cardinality match (ensuring no extraneous outbounds are active)
		if len(actualSelectors) != len(expectedSlots) {
			return fmt.Errorf("runtime read-back mismatch: balancer %s has %d selectors, expected %d (actual: %v)",
				expectedBalancer, len(actualSelectors), len(expectedSlots), actualSelectors)
		}
	}

	log.Printf("[XraySupervisor] Runtime read-back VERIFIED: active slots=%v, draining slot %d excluded", expectedSlots, drainingSlot)
	return nil
}

func (s *Supervisor) getActiveSlotsLocked() []int {
	var active []int
	for i := 0; i < s.slotCount; i++ {
		t := fmt.Sprintf("exit-%d", i)
		if s.activeOutbounds[t] {
			active = append(active, i)
		}
	}
	sort.Ints(active)
	return active
}

// DrainingSlot transitions a slot to DRAINING using a candidate-commit transactional model.
// It removes the slot from active routing via Xray API adrules so new connections
// will never route to this slot, while existing TCP streams remain alive on their socket.
// It performs a runtime read-back to strictly guarantee the draining slot is excluded.
func (s *Supervisor) DrainingSlot(slot int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tag := fmt.Sprintf("exit-%d", slot)
	if !s.activeOutbounds[tag] {
		log.Printf("[XraySupervisor] Slot %d (%s) is already not active", slot, tag)
		return nil
	}

	oldSlots := s.getActiveSlotsLocked()
	surviving := []int{}
	for _, sl := range oldSlots {
		if sl != slot {
			surviving = append(surviving, sl)
		}
	}

	// 1. Apply candidate state to runtime and verify
	if err := s.applyCandidateRoutingLocked(surviving, slot); err != nil {
		// Rollback runtime to old state
		if rbErr := s.applyCandidateRoutingLocked(oldSlots, -1); rbErr != nil {
			log.Printf("[XraySupervisor] CRITICAL SAFETY STATE: rollback after drain slot %d failed: %v", slot, rbErr)
		}
		return fmt.Errorf("failed to drain slot %d in Xray runtime: %w", slot, err)
	}

	// 2. COMMIT memory state ONLY after runtime application and verification succeed
	s.activeOutbounds[tag] = false
	log.Printf("[XraySupervisor] Slot %d draining TRANSACTION COMMITTED (surviving=%v)", slot, surviving)
	return nil
}

// ActivateSlot promotes a slot to ACTIVE status using a candidate-commit transactional model.
func (s *Supervisor) ActivateSlot(slot int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tag := fmt.Sprintf("exit-%d", slot)
	if s.activeOutbounds[tag] {
		return nil
	}

	oldSlots := s.getActiveSlotsLocked()
	candidateSet := make(map[int]bool)
	for _, sl := range oldSlots {
		candidateSet[sl] = true
	}
	candidateSet[slot] = true

	candidateSlots := make([]int, 0, len(candidateSet))
	for sl := range candidateSet {
		candidateSlots = append(candidateSlots, sl)
	}
	sort.Ints(candidateSlots)

	// 1. Apply candidate state to runtime and verify
	if err := s.applyCandidateRoutingLocked(candidateSlots, -1); err != nil {
		// Rollback runtime to old state
		if rbErr := s.applyCandidateRoutingLocked(oldSlots, -1); rbErr != nil {
			log.Printf("[XraySupervisor] CRITICAL SAFETY STATE: rollback after activate slot %d failed: %v", slot, rbErr)
		}
		return fmt.Errorf("failed to activate slot %d in Xray runtime: %w", slot, err)
	}

	// 2. COMMIT memory state ONLY after runtime application and verification succeed
	s.activeOutbounds[tag] = true
	log.Printf("[XraySupervisor] Slot %d activation TRANSACTION COMMITTED (active=%v)", slot, candidateSlots)
	return nil
}

// GetActiveSlots returns the list of slot indices currently active in Xray.
func (s *Supervisor) GetActiveSlots() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []int
	for tag, isAct := range s.activeOutbounds {
		if isAct {
			var slot int
			if _, err := fmt.Sscanf(tag, "exit-%d", &slot); err == nil {
				active = append(active, slot)
			}
		}
	}
	sort.Ints(active)
	return active
}

// GetOutboundStats queries Xray's StatsService for uplink and downlink bytes of a specific outbound tag.
func (s *Supervisor) GetOutboundStats(tag string) (int64, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state != StateRunning {
		return 0, 0, errors.New("xray supervisor is not running")
	}

	queryStat := func(metric string) (int64, error) {
		name := fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, metric)
		/* #nosec G204 */
		cmd := exec.Command(s.xrayBin, "api", "stats", "--server="+s.apiAddr, "-name", name)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("failed to query %s: %w (output: %s)", name, err, string(out))
		}
		var resp struct {
			Stat struct {
				Name  string `json:"name"`
				Value int64  `json:"value"`
			} `json:"stat"`
		}
		if err := json.Unmarshal(out, &resp); err == nil {
			return resp.Stat.Value, nil
		}
		return 0, nil
	}

	uplink, errUp := queryStat("uplink")
	if errUp != nil {
		return 0, 0, errUp
	}
	downlink, errDown := queryStat("downlink")
	if errDown != nil {
		return 0, 0, errDown
	}
	return uplink, downlink, nil
}

// DisableOutbound gracefully drains an outbound without calling rmo,
// preserving existing connections while excluding the slot from new routing.
func (s *Supervisor) DisableOutbound(tag string) error {
	slotStr := strings.TrimPrefix(tag, "exit-")
	slot, err := strconv.Atoi(slotStr)
	if err != nil {
		s.mu.Lock()
		s.activeOutbounds[tag] = false
		s.mu.Unlock()
		return nil
	}
	return s.DrainingSlot(slot)
}

// EnableOutbound promotes an outbound to active routing via ActivateSlot.
func (s *Supervisor) EnableOutbound(tag string, mark int) error {
	s.mu.Lock()
	s.outboundMarks[tag] = mark
	s.mu.Unlock()

	slotStr := strings.TrimPrefix(tag, "exit-")
	slot, err := strconv.Atoi(slotStr)
	if err != nil {
		s.mu.Lock()
		s.activeOutbounds[tag] = true
		s.mu.Unlock()
		return nil
	}
	return s.ActivateSlot(slot)
}

// IsOutboundActive checks if a given outbound tag is currently in the active set.
func (s *Supervisor) IsOutboundActive(tag string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeOutbounds[tag]
}

// GetState returns the current supervisor state and metrics.
func (s *Supervisor) GetState() (SupervisorState, int, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state, s.restarts, s.lastRestart
}

// Stop gracefully shuts down the Xray process and cancels background monitoring.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.state = StateStopped
	s.cancel()
	cmd := s.cmd
	done := s.processDone
	s.mu.Unlock()

	log.Println("[XraySupervisor] Stopping Xray process...")

	if cmd != nil && cmd.Process != nil && done != nil {
		// Send SIGTERM
		_ = cmd.Process.Signal(syscall.SIGTERM)

		select {
		case <-done:
			log.Println("[XraySupervisor] Xray exited cleanly.")
		case <-time.After(5 * time.Second):
			log.Println("[XraySupervisor] Xray did not exit within 5s, sending SIGKILL...")
			_ = cmd.Process.Kill()
			<-done
			log.Println("[XraySupervisor] Xray killed.")
		}
	}

	s.wg.Wait()
	return nil
}

func (s *Supervisor) killCurrentProcess() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Kill()
	}
	return nil
}
