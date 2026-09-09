package scheduler

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// GetActiveConnectionCount returns the number of active connections for a specific slot
// by querying the kernel conntrack table using the slot's fwmark.
func GetActiveConnectionCount(slotIndex int) (int, error) {
	// The fwmark for a slot is BaseTableID + slotIndex
	fwmark := routing.BaseTableID + slotIndex

	/* #nosec G204 */
	cmd := exec.Command("conntrack", "-L", "-m", fmt.Sprintf("%d", fwmark))
	output, err := cmd.CombinedOutput()
	
	// conntrack returns exit code 1 if 0 flow entries are found.
	// So we don't treat err != nil as a fatal error unless it's a command not found error.
	if err != nil {
		if strings.Contains(string(output), "command not found") {
			return 0, fmt.Errorf("conntrack tool not found: %w", err)
		}
		// If there's an error but output is empty or says 0 flow entries, it means 0 connections.
		return 0, nil
	}

	// Output example:
	// tcp      6 431999 ESTABLISHED src=192.168.1.1 dst=8.8.8.8 sport=12345 dport=443 src=8.8.8.8 dst=10.0.0.1 sport=443 dport=12345 [ASSURED] mark=100 use=1
	// conntrack v1.4.6 (conntrack-tools): 1 flow entries have been shown.
	
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	count := 0
	for _, line := range lines {
		// Ignore the summary line at the bottom
		if strings.HasPrefix(line, "conntrack") {
			continue
		}
		if strings.Contains(line, fmt.Sprintf("mark=%d", fwmark)) {
			// Additionally, we might filter out TIME_WAIT connections if we only want ESTABLISHED,
			// but UDP uses session affinity so we count all tracked connections.
			count++
		}
	}

	return count, nil
}

// FormatDrainingStatus provides a loggable summary of draining connections
func FormatDrainingStatus(slotIndex int, count int) string {
	return "Slot " + strconv.Itoa(slotIndex) + " draining: " + strconv.Itoa(count) + " active connections"
}
