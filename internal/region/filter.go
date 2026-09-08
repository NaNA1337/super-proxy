package region

import (
	"strings"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
)

// FilterNodes filters the discovered nodes based on the region policy
func FilterNodes(nodes []models.Node, cfg config.RegionConfig, minRequired int) []models.Node {
	var primaryNodes []models.Node
	var fallbackNodes []models.Node

	primaryRegion := strings.ToUpper(cfg.Primary)
	fallbackMap := make(map[string]bool)
	for _, f := range cfg.Fallback {
		fallbackMap[strings.ToUpper(f)] = true
	}

	for _, node := range nodes {
		nodeRegion := strings.ToUpper(node.Country)
		if nodeRegion == primaryRegion {
			primaryNodes = append(primaryNodes, node)
		} else if fallbackMap[nodeRegion] {
			fallbackNodes = append(fallbackNodes, node)
		}
	}

	// If primary nodes meet the minimum required, we strictly use primary
	if len(primaryNodes) >= minRequired {
		return primaryNodes
	}

	// Otherwise, append fallback nodes
	return append(primaryNodes, fallbackNodes...)
}
