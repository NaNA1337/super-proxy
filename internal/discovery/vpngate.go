package discovery

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

// ovpnSecretCache stores raw Base64 OVPN configs in-memory ONLY.
// These secrets NEVER touch the database. Keyed by node IP.
var (
	ovpnSecretCacheMu sync.RWMutex
	ovpnSecretCache   = make(map[string]string)
)

// GetOVPNSecret retrieves the raw Base64 OVPN config for a node from the in-memory cache.
// Returns ("", false) if no config is cached (e.g., after daemon restart before first discovery).
func GetOVPNSecret(nodeIP string) (string, bool) {
	ovpnSecretCacheMu.RLock()
	defer ovpnSecretCacheMu.RUnlock()
	val, ok := ovpnSecretCache[nodeIP]
	return val, ok
}

// DeleteOVPNSecret removes a node's raw OVPN config from the in-memory cache.
func DeleteOVPNSecret(nodeIP string) {
	ovpnSecretCacheMu.Lock()
	defer ovpnSecretCacheMu.Unlock()
	delete(ovpnSecretCache, nodeIP)
}

// ClearOVPNSecretCache wipes all cached OVPN secrets from memory.
func ClearOVPNSecretCache() {
	ovpnSecretCacheMu.Lock()
	defer ovpnSecretCacheMu.Unlock()
	ovpnSecretCache = make(map[string]string)
}

// OVPNSecretCacheSize returns the number of cached OVPN secrets (for testing/metrics).
func OVPNSecretCacheSize() int {
	ovpnSecretCacheMu.RLock()
	defer ovpnSecretCacheMu.RUnlock()
	return len(ovpnSecretCache)
}

// FetchAndParseNodes downloads the VPN Gate CSV and parses it into Node models
func FetchAndParseNodes(url string) ([]models.Node, error) {
	log.Printf("Fetching VPN Gate data from %s", url)
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nodes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return parseCSV(resp.Body)
}

func parseCSV(reader io.Reader) ([]models.Node, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1 // Allow variable number of fields, just in case
	csvReader.LazyQuotes = true

	var nodes []models.Node
	now := time.Now()

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Warning: error reading CSV record: %v", err)
			continue
		}

		// Skip comments and empty lines
		if len(record) == 0 || strings.HasPrefix(record[0], "*") || strings.HasPrefix(record[0], "#") {
			continue
		}

		// VPN Gate format: HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
		if len(record) < 15 {
			continue
		}

		score, _ := strconv.Atoi(record[2])
		ping, _ := strconv.Atoi(record[3])
		speed, _ := strconv.ParseInt(record[4], 10, 64)
		sessions, _ := strconv.Atoi(record[7])
		uptime, _ := strconv.ParseInt(record[8], 10, 64)
		users, _ := strconv.Atoi(record[9])

		ip := record[1]
		totalTraffic, _ := strconv.ParseInt(record[10], 10, 64)
		logType := record[11]
		operator := record[12]
		b64Config := record[14]

		rawConfig, meta, err := ParseOpenVPNConfig(b64Config)
		if err != nil {
			log.Printf("[Discovery] Rejecting node %s (%s): invalid OpenVPN config: %v", ip, record[0], err)
			continue
		}

		endpointsJSON, _ := json.Marshal(meta.Endpoints)

		// Store raw Base64 OVPN config in runtime-only in-memory cache.
		// This secret NEVER reaches the database.
		ovpnSecretCacheMu.Lock()
		ovpnSecretCache[ip] = b64Config
		ovpnSecretCacheMu.Unlock()

		id := ip

		node := models.Node{
			ID:            id,
			HostName:      record[0],
			IP:            ip,
			Score:         score,
			CountryL:      record[5],
			Country:       record[6], // CountryShort
			Sessions:      sessions,
			Uptime:        uptime,
			Users:         users,
			TotalTraffic:  totalTraffic,
			LogType:       logType,
			Operator:      operator,
			Message:       record[13],
			OpenVPN:       "", // SECURITY: Never persist raw OVPN to DB. Secret lives only in ovpnSecretCache.
			OpenVPNConfig: StripSecrets(rawConfig),
			EndpointsJSON: string(endpointsJSON),
			EndpointHost:  meta.PrimaryEndpoint.Host,
			EndpointPort:  meta.PrimaryEndpoint.Port,
			EndpointProto: meta.PrimaryEndpoint.Proto,
			Status:        models.StatusDiscovered,
			LastSeen:      now,
			FirstSeen:     now,
			FailCount:     0,
			Performance: models.PerformanceMetrics{
				RTT:        ping,
				Throughput: speed,
			},
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}
