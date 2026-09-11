package agentapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/routing"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/NaNA1337/super-proxy/internal/xray"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	appStartTime  = time.Now()
	sched         *scheduler.Scheduler
	activeVlessMu sync.RWMutex
	activeVless   *xray.VlessConfig
)

// SetActiveVlessConfig sets the active VLESS Reality configuration.
func SetActiveVlessConfig(cfg *xray.VlessConfig) {
	activeVlessMu.Lock()
	defer activeVlessMu.Unlock()
	activeVless = cfg
}

// GetActiveVlessConfig retrieves the active VLESS Reality configuration.
func GetActiveVlessConfig() *xray.VlessConfig {
	activeVlessMu.RLock()
	defer activeVlessMu.RUnlock()
	return activeVless
}

// SetScheduler injects the global scheduler into the API handlers
func SetScheduler(s *scheduler.Scheduler) {
	sched = s
}

var buildVersion = "dev"

func SetVersion(version string) { buildVersion = version }

func handleHealthLive(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    int64(time.Since(appStartTime).Seconds()),
	})
}

func handleHealthReady(w http.ResponseWriter, r *http.Request) {
	isReady := true
	reasons := make([]string, 0)

	if database.DB == nil {
		isReady = false
		reasons = append(reasons, "database connection is uninitialized")
	} else {
		sqlDB, err := database.DB.DB()
		if err != nil || sqlDB.Ping() != nil {
			isReady = false
			reasons = append(reasons, "database ping failed")
		}
	}

	if sched == nil {
		isReady = false
		reasons = append(reasons, "scheduler engine is not initialized")
	}

	if !isReady {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "not_ready",
			"reasons": reasons,
		})
		return
	}

	sendJSON(w, map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	resp := map[string]interface{}{
		"server_id": hostname,
		"name":      "Super-Proxy Egress Manager",
		"region":    os.Getenv("XRAY_MANAGER_REGION"), // E.g., JP
		"version":   buildVersion,
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

	exits := make([]map[string]interface{}, 0)
	for slot, tunnel := range sched.ActiveSlots {
		exitIP := tunnel.Node.ObservedExitIP
		if exitIP == "" {
			exitIP = tunnel.Node.IP
		}
		exits = append(exits, map[string]interface{}{
			"slot":        slot,
			"status":      tunnel.State,
			"node_id":     tunnel.Node.ID,
			"ip":          exitIP,
			"endpoint_ip": tunnel.Node.IP,
			"interface":   tunnel.Interface,
			"country":     tunnel.Node.Country,
			"region":      tunnel.Node.Country, // Simplified mapping
			"score":       tunnel.Node.Score,
			"reputation":  tunnel.Node.Reputation,
			"throughput":  tunnel.Node.Performance.Throughput,
			"last_check":  tunnel.Node.LastSeen,
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
	nodes := make([]models.Node, 0)
	// Only return nodes that have been vetted (DISCOVERED/STANDBY)
	database.DB.Where("status IN ?", []string{"DISCOVERED", "STANDBY"}).Find(&nodes)

	// Strip out raw credentials and sanitize config for list endpoints
	for i := range nodes {
		nodes[i].OpenVPN = ""
		nodes[i].OpenVPNConfig = discovery.StripSecrets(nodes[i].OpenVPNConfig)
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

	// Guarantee that raw credentials and private keys never leave via API
	node.OpenVPN = ""
	node.OpenVPNConfig = discovery.StripSecrets(node.OpenVPNConfig)

	sendJSON(w, node)
}

func sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

type NodeListResponse struct {
	Total int64         `json:"total"`
	Nodes []models.Node `json:"nodes"`
}

func handleNodesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := database.DB.Model(&models.Node{})

	country := r.URL.Query().Get("country")
	if country != "" {
		query = query.Where("country = ?", country)
	}

	status := r.URL.Query().Get("status")
	if status != "" {
		query = query.Where("status = ?", status)
	}

	search := r.URL.Query().Get("search")
	if search != "" {
		query = query.Where("ip LIKE ? OR host_name LIKE ? OR rep_details LIKE ? OR net_asn LIKE ? OR net_isp LIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	var total int64
	query.Count(&total)

	limit := 100
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	offset := 0
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	nodes := make([]models.Node, 0)
	query.Order("score DESC, uptime DESC").Limit(limit).Offset(offset).Find(&nodes)

	for i := range nodes {
		nodes[i].OpenVPN = ""
		nodes[i].OpenVPNConfig = discovery.StripSecrets(nodes[i].OpenVPNConfig)
	}

	sendJSON(w, NodeListResponse{
		Total: total,
		Nodes: nodes,
	})
}

func handleRoutingOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type SlotRouteInfo struct {
		Slot      int    `json:"slot"`
		TableID   int    `json:"table_id"`
		Fwmark    int    `json:"fwmark"`
		Interface string `json:"interface"`
		NodeIP    string `json:"node_ip"`
		Country   string `json:"country"`
		Status    string `json:"status"`
	}

	var routes []SlotRouteInfo

	if sched != nil {
		sched.Mu.Lock()
		for i := 0; i < sched.MaxActive; i++ {
			tableID := routing.BaseTableID + i
			info := SlotRouteInfo{
				Slot:      i,
				TableID:   tableID,
				Fwmark:    tableID,
				Interface: fmt.Sprintf("tun%d", i),
				Status:    "OFFLINE",
			}
			if tunnel, ok := sched.ActiveSlots[i]; ok && tunnel != nil {
				info.Status = tunnel.State
				info.Interface = tunnel.Interface
				if tunnel.Node != nil {
					info.NodeIP = tunnel.Node.IP
					info.Country = tunnel.Node.Country
				}
			}
			routes = append(routes, info)
		}
		sched.Mu.Unlock()
	}

	resp := map[string]interface{}{
		"slots":               routes,
		"dns_leak_protected":  true,
		"ipv6_leak_protected": true,
	}
	sendJSON(w, resp)
}

func handleClientConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	protocols := []string{"socks5"}

	profile, err := BuildRealityClientProfile(r)
	var vlessConfig map[string]interface{}
	if err == nil && profile != nil {
		protocols = append(protocols, "vless")
		shareLink, _ := BuildVlessShareLink(profile)
		clashProxy, _ := BuildClashMetaProxyItem(profile)
		singboxOutbound, _ := BuildSingboxOutboundItem(profile)
		xrayConfig, _ := BuildXrayClientConfig(profile)
		rawSub, _ := BuildSubscription(profile)

		vlessConfig = map[string]interface{}{
			"address":            profile.Address,
			"port":               profile.Port,
			"uuid":               profile.UUID,
			"security":           profile.Security,
			"server_name":        profile.SNI,
			"fingerprint":        profile.Fingerprint,
			"public_key":         profile.PublicKey,
			"short_id":           profile.ShortID,
			"flow":               profile.Flow,
			"reality_target":     profile.RealityTarget,
			"type":               "tcp",
			"outbound_only_443":  profile.OutboundOnly443,
			"only_port_443":      profile.OutboundOnly443,
			"share_link":         shareLink,
			"raw_subscription":   rawSub,
			"clash_meta_proxy":   clashProxy,
			"sing_box_outbound":  singboxOutbound,
			"xray_client_config": xrayConfig,
			"export_endpoints": map[string]string{
				"all":     "/api/v1/client-config/all",
				"clash":   "/api/v1/export/clash",
				"singbox": "/api/v1/export/singbox",
				"xray":    "/api/v1/export/xray",
				"sub":     "/api/v1/export/sub",
			},
		}
	}

	sPort := 1080
	if p, err := strconv.Atoi(os.Getenv("XRAY_SOCKS_PORT")); err == nil && p > 0 {
		sPort = p
	}
	sAddr := os.Getenv("XRAY_SOCKS_ADDR")
	if sAddr == "" {
		sAddr = "127.0.0.1"
	}

	resp := map[string]interface{}{
		"protocols": protocols,
		"socks": map[string]interface{}{
			"address": sAddr,
			"port":    sPort,
			"auth":    false,
		},
	}
	if vlessConfig != nil {
		resp["vless"] = vlessConfig
	}

	sendJSON(w, resp)
}
