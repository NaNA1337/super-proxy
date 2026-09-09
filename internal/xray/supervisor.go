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

	// Callbacks for metrics and observability
	OnCrash   func(err error)
	OnRestart func(attempt int)
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
		activeMap[tag] = true
		marksMap[tag] = 100 + i // base table
	}

	return &Supervisor{
		configPath:      configPath,
		apiAddr:         fmt.Sprintf("127.0.0.1:%d", apiPort),
		socksAddr:       fmt.Sprintf("%s:%d", socksListen, socksPort),
		xrayBin:         xrayBin,
		slotCount:       slotCount,
		state:           StateStopped,
		activeOutbounds: activeMap,
		outboundMarks:   marksMap,
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
		return errors.New("xray supervisor is already running or starting")
	}
	s.stopped = false
	s.state = StateStarting
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

// DisableOutbound removes an outbound tag from Xray's active balancer set via Xray API.
func (s *Supervisor) DisableOutbound(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.activeOutbounds[tag] {
		log.Printf("[XraySupervisor] Outbound %s is already disabled", tag)
		return nil
	}

	/* #nosec G204 */
	cmd := exec.Command(s.xrayBin, "api", "rmo", "--server="+s.apiAddr, tag)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove outbound %s via xray api: %w (output: %s)", tag, err, string(out))
	}

	s.activeOutbounds[tag] = false
	log.Printf("[XraySupervisor] Outbound %s successfully REMOVED from Xray active set", tag)
	return nil
}

// EnableOutbound dynamically adds an outbound tag with its fwmark to Xray via Xray API.
func (s *Supervisor) EnableOutbound(tag string, mark int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeOutbounds[tag] {
		log.Printf("[XraySupervisor] Outbound %s is already active", tag)
		return nil
	}

	outboundDef := map[string]interface{}{
		"tag":      tag,
		"protocol": "freedom",
		"settings": map[string]interface{}{},
		"streamSettings": map[string]interface{}{
			"sockopt": map[string]interface{}{
				"mark": mark,
			},
		},
	}

	configWrapper := map[string]interface{}{
		"outbounds": []interface{}{outboundDef},
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("xray_outbound_%s_*.json", tag))
	if err != nil {
		return fmt.Errorf("failed to create temp outbound json: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if err := json.NewEncoder(tmpFile).Encode(configWrapper); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to encode outbound json: %w", err)
	}
	_ = tmpFile.Close()

	/* #nosec G204 */
	cmd := exec.Command(s.xrayBin, "api", "ado", "--server="+s.apiAddr, tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add outbound %s via xray api: %w (output: %s)", tag, err, string(out))
	}

	s.activeOutbounds[tag] = true
	s.outboundMarks[tag] = mark
	log.Printf("[XraySupervisor] Outbound %s (mark: %d) successfully ADDED to Xray active set", tag, mark)
	return nil
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
