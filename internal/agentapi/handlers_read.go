package agentapi

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	appStartTime = time.Now()
	sched        *scheduler.Scheduler
)

// SetScheduler injects the global scheduler into the API handlers
func SetScheduler(s *scheduler.Scheduler) {
	sched = s
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	resp := map[string]interface{}{
		"server_id": hostname,
		"name":      "Super-Proxy Egress Manager",
		"region":    os.Getenv("XRAY_MANAGER_REGION"), // E.g., JP
		"version":   "1.0.0",
		"status":    "online",
		"uptime":    int64(time.Since(appStartTime).Seconds()),
	}
	sendJSON(w, resp)
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	v, _ := mem.VirtualMemory()
	c, _ := cpu.Percent(0, false)
	h, _ := host.Info()
	n, _ := net.IOCounters(false)

	var cpuPercent float64
	if len(c) > 0 {
		cpuPercent = c[0]
	}

	var rx, tx uint64
	if len(n) > 0 {
		rx = n[0].BytesRecv
		tx = n[0].BytesSent
	}

	resp := map[string]interface{}{
		"OS":     h.OS,
		"CPU":    cpuPercent,
		"Memory": v.UsedPercent,
		"Uptime": h.Uptime,
		"RX":     rx,
		"TX":     tx,
	}
	sendJSON(w, resp)
}

func handleCurrentExits(w http.ResponseWriter, r *http.Request) {
	if sched == nil {
		http.Error(w, "Scheduler not initialized", http.StatusInternalServerError)
		return
	}

	sched.Mu.Lock()
	defer sched.Mu.Unlock()

	var exits []map[string]interface{}
	for slot, tunnel := range sched.ActiveSlots {
		exits = append(exits, map[string]interface{}{
			"slot":         slot,
			"status":       tunnel.IsActive,
			"node_id":      tunnel.Node.ID,
			"ip":           tunnel.Node.IP,
			"country":      tunnel.Node.Country,
			"region":       tunnel.Node.Country, // Simplified mapping
			"score":        tunnel.Node.Score,
			"reputation":   tunnel.Node.HealthScore, // Rep map
			"throughput":   tunnel.Node.Speed,
			"last_check":   tunnel.Node.LastSeen,
		})
	}
	sendJSON(w, exits)
}

func handleSlots(w http.ResponseWriter, r *http.Request) {
	if sched == nil {
		http.Error(w, "Scheduler not initialized", http.StatusInternalServerError)
		return
	}

	sched.Mu.Lock()
	defer sched.Mu.Unlock()
	
	slots := make(map[int]string)
	for k, v := range sched.ActiveSlots {
		slots[k] = v.Node.ID
	}
	
	sendJSON(w, map[string]interface{}{
		"total_configured": sched.MaxActive,
		"slots":            slots,
		"manual_overrides": sched.ManualOverride,
	})
}

func handlePool(w http.ResponseWriter, r *http.Request) {
	var counts []struct {
		Status string
		Count  int
	}
	
	database.DB.Model(&models.Node{}).Select("status, count(*) as count").Group("status").Scan(&counts)
	
	resp := map[string]int{
		"active":    0,
		"standby":   0,
		"qualified": 0, // We map DISCOVERED to qualified here based on requirements
		"candidate": 0, // NEW
		"cooldown":  0,
		"rejected":  0, // DEAD/FAILED
	}

	for _, c := range counts {
		switch c.Status {
		case "ACTIVE":
			resp["active"] = c.Count
		case "STANDBY":
			resp["standby"] = c.Count
		case "DISCOVERED":
			resp["qualified"] = c.Count
		case "NEW":
			resp["candidate"] = c.Count
		case "COOLDOWN":
			resp["cooldown"] = c.Count
		case "FAILED", "DEAD":
			resp["rejected"] += c.Count
		}
	}
	
	sendJSON(w, resp)
}

func handlePoolQualified(w http.ResponseWriter, r *http.Request) {
	var nodes []models.Node
	// Only return nodes that have been vetted (DISCOVERED/STANDBY)
	database.DB.Where("status IN ?", []string{"DISCOVERED", "STANDBY"}).Find(&nodes)
	
	// Strip out the massive OpenVPN base64 config for list endpoints to save bandwidth
	for i := range nodes {
		nodes[i].OpenVPN = ""
	}
	sendJSON(w, nodes)
}

func handleNodeDetails(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid node ID", http.StatusBadRequest)
		return
	}
	nodeID := parts[4]

	var node models.Node
	result := database.DB.Where("id = ?", nodeID).First(&node)
	if result.Error != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	sendJSON(w, node)
}

func sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
