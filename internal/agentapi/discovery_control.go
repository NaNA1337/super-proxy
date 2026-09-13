package agentapi

import (
	"net/http"
	"sync"

	"github.com/NaNA1337/super-proxy/internal/discovery"
)

var (
	discoveryCoordinatorMu sync.RWMutex
	discoveryCoordinator   *discovery.RefreshCoordinator
)

func SetDiscoveryCoordinator(coordinator *discovery.RefreshCoordinator) {
	discoveryCoordinatorMu.Lock()
	discoveryCoordinator = coordinator
	discoveryCoordinatorMu.Unlock()
}

func getDiscoveryCoordinator() *discovery.RefreshCoordinator {
	discoveryCoordinatorMu.RLock()
	defer discoveryCoordinatorMu.RUnlock()
	return discoveryCoordinator
}

func handleDiscoveryRefresh(w http.ResponseWriter, r *http.Request) {
	coordinator := getDiscoveryCoordinator()
	if coordinator == nil {
		http.Error(w, `{"error":"discovery refresh is unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		sendJSON(w, map[string]interface{}{"started": false, "status": coordinator.Status()})
	case http.MethodPost:
		status, started := coordinator.Trigger("manual")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		sendJSON(w, map[string]interface{}{"started": started, "status": status})
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
