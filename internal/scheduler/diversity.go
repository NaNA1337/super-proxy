package scheduler

import (
	"fmt"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

// CheckPrefixDiversity rejects a candidate when either its endpoint or observed
// egress shares an IPv4 /24 with another active or standby tunnel.
func (s *Scheduler) CheckPrefixDiversity(candidate *models.Node, observedIP string, excludeActiveSlot int) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.CheckPrefixDiversityLocked(candidate, observedIP, excludeActiveSlot)
}

// CheckPrefixDiversityLocked performs the same check while the caller already
// holds Scheduler.Mu. It is used at atomic reservation/commit boundaries.
func (s *Scheduler) CheckPrefixDiversityLocked(candidate *models.Node, observedIP string, excludeActiveSlot int) error {
	if candidate == nil {
		return fmt.Errorf("candidate node is nil")
	}
	candidatePrefixes := nodePrefixes(candidate, observedIP)
	if len(candidatePrefixes) == 0 {
		return fmt.Errorf("candidate %s has no valid IPv4 /24 prefix", candidate.ID)
	}

	for slot, tunnel := range s.ActiveSlots {
		if slot == excludeActiveSlot {
			continue
		}
		if err := prefixConflict(candidate, candidatePrefixes, tunnel, fmt.Sprintf("active slot %d", slot)); err != nil {
			return err
		}
	}
	for index, tunnel := range s.StandbyNodes {
		if err := prefixConflict(candidate, candidatePrefixes, tunnel, fmt.Sprintf("standby %d", index)); err != nil {
			return err
		}
	}
	return nil
}

func prefixConflict(candidate *models.Node, candidatePrefixes map[string]string, tunnel *openvpn.Tunnel, location string) error {
	if tunnel == nil || tunnel.Node == nil || tunnel.Node.ID == candidate.ID {
		return nil
	}
	for prefix, candidateIP := range candidatePrefixes {
		if existingIP, exists := nodePrefixes(tunnel.Node, "")[prefix]; exists {
			return fmt.Errorf("IPv4 /24 conflict: candidate %s (%s) and %s node %s (%s) share %s",
				candidate.ID, candidateIP, location, tunnel.Node.ID, existingIP, prefix)
		}
	}
	return nil
}

func nodePrefixes(node *models.Node, extraIP string) map[string]string {
	result := make(map[string]string)
	if node == nil {
		return result
	}
	for _, ip := range []string{node.IP, node.ObservedExitIP, extraIP} {
		ip = strings.TrimSpace(ip)
		if prefix := reputation.AnalyzePrefix(ip); prefix != "" {
			result[prefix] = ip
		}
	}
	return result
}
