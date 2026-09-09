package scheduler

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// ConnectionCountUnknown indicates conntrack query failed or was unavailable.
const ConnectionCountUnknown = -1

var conntrackCmd = "conntrack"

// GetActiveConnectionCount returns the number of active connections for a specific slot/tunnel
// by querying the kernel conntrack table using the slot's fwmark or the tunnel IP.
// If the tool fails or conntrack is unreadable, it returns ConnectionCountUnknown with the error.
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
	cmd := exec.Command(conntrackCmd, args...)
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// Legitimate 0 flow entries check:
	// conntrack returns "0 flow entries have been shown." (with exit code 0 or 1 depending on version)
	if strings.Contains(outStr, "0 flow entries") || (err == nil && strings.TrimSpace(outStr) == "") {
		return 0, nil
	}

	// Any execution failure must return ConnectionCountUnknown
	if err != nil {
		if strings.Contains(outStr, "command not found") {
			return ConnectionCountUnknown, fmt.Errorf("conntrack tool not found: %w", err)
		}
		return ConnectionCountUnknown, fmt.Errorf("conntrack command failed: %w (output: %s)", err, strings.TrimSpace(outStr))
	}

	lines := strings.Split(strings.TrimSpace(outStr), "\n")
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
	if count == ConnectionCountUnknown {
		return "Slot " + strconv.Itoa(slotIndex) + " draining: connections UNKNOWN"
	}
	return "Slot " + strconv.Itoa(slotIndex) + " draining: " + strconv.Itoa(count) + " active connections"
}
