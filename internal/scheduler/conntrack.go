package scheduler

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// GetActiveConnectionCount returns the number of active connections for a specific slot/tunnel
// by querying the kernel conntrack table using the slot's fwmark or the tunnel IP.
func GetActiveConnectionCount(slotIndex int, tunIP string) (int, error) {
	fwmark := routing.BaseTableID + slotIndex

	// Try querying by tunIP if provided, otherwise by mark
	args := []string{"-L"}
	if tunIP != "" {
		args = append(args, "-s", tunIP)
	} else {
		args = append(args, "-m", fmt.Sprintf("%d", fwmark))
	}

	/* #nosec G204 */
	cmd := exec.Command("conntrack", args...)
	output, err := cmd.CombinedOutput()

	// conntrack returns exit code 1 if 0 flow entries are found.
	if err != nil {
		if strings.Contains(string(output), "command not found") {
			return 0, fmt.Errorf("conntrack tool not found: %w", err)
		}
		// 0 entries found
		return 0, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "conntrack") {
			continue
		}
		if tunIP != "" && strings.Contains(line, fmt.Sprintf("src=%s", tunIP)) {
			count++
		} else if strings.Contains(line, fmt.Sprintf("mark=%d", fwmark)) {
			count++
		}
	}

	return count, nil
}

// FormatDrainingStatus provides a loggable summary of draining connections
func FormatDrainingStatus(slotIndex int, count int) string {
	return "Slot " + strconv.Itoa(slotIndex) + " draining: " + strconv.Itoa(count) + " active connections"
}
