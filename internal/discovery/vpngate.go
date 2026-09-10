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

// secretEntry holds the cached raw Base64 OVPN credentials with timestamp and TTL.
type secretEntry struct {
	secret    string
	createdAt time.Time
	expiresAt time.Time
}

// DefaultSecretTTL defines how long cached OVPN secrets remain valid without rediscovery.
const DefaultSecretTTL = 2 * time.Hour

// ovpnSecretCache stores raw Base64 OVPN configs in-memory ONLY.
// These secrets NEVER touch the database. Keyed by stable Node ID.
var (
	ovpnSecretCacheMu sync.RWMutex
	ovpnSecretCache   = make(map[string]secretEntry)
)

// SetOVPNSecret stores a node's raw Base64 OVPN secret in memory with a TTL.
// Keyed by stable Node ID.
func SetOVPNSecret(nodeID string, secret string, ttl ...time.Duration) {
	if nodeID == "" || secret == "" {
		return
	}
	d := DefaultSecretTTL
	if len(ttl) > 0 && ttl[0] > 0 {
		d = ttl[0]
	}
	now := time.Now()
	ovpnSecretCacheMu.Lock()
	defer ovpnSecretCacheMu.Unlock()
	ovpnSecretCache[nodeID] = secretEntry{
		secret:    secret,
		createdAt: now,
		expiresAt: now.Add(d),
	}
}

// GetOVPNSecret retrieves the raw Base64 OVPN config for a node from the in-memory cache.
// Keyed by stable Node ID. Returns ("", false) if not found or expired.
func GetOVPNSecret(nodeID string) (string, bool) {
	ovpnSecretCacheMu.RLock()
	entry, ok := ovpnSecretCache[nodeID]
	ovpnSecretCacheMu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		// Lazy eviction of expired entry
		ovpnSecretCacheMu.Lock()
		if e, exists := ovpnSecretCache[nodeID]; exists && time.Now().After(e.expiresAt) {
			delete(ovpnSecretCache, nodeID)
		}
		ovpnSecretCacheMu.Unlock()
		return "", false
	}
	return entry.secret, true
}

// DeleteOVPNSecret removes a node's raw OVPN config from the in-memory cache.
// Used when a node transitions to DEAD/FAILED or is deleted from database.
func DeleteOVPNSecret(nodeID string) {
	ovpnSecretCacheMu.Lock()
	defer ovpnSecretCacheMu.Unlock()
	delete(ovpnSecretCache, nodeID)
}

// EvictExpiredSecrets scans the cache and purges all entries whose TTL has passed.
// Returns the number of purged entries.
func EvictExpiredSecrets() int {
	now := time.Now()
	ovpnSecretCacheMu.Lock()
	defer ovpnSecretCacheMu.Unlock()
	evicted := 0
	for id, entry := range ovpnSecretCache {
		if now.After(entry.expiresAt) {
			delete(ovpnSecretCache, id)
			evicted++
		}
	}
	return evicted
}

// ClearOVPNSecretCache wipes all cached OVPN secrets from memory.
func ClearOVPNSecretCache() {
	ovpnSecretCacheMu.Lock()
	defer ovpnSecretCacheMu.Unlock()
	ovpnSecretCache = make(map[string]secretEntry)
}

// OVPNSecretCacheSize returns the number of active, non-expired cached OVPN secrets.
func OVPNSecretCacheSize() int {
	now := time.Now()
	ovpnSecretCacheMu.RLock()
	defer ovpnSecretCacheMu.RUnlock()
	count := 0
	for _, entry := range ovpnSecretCache {
		if now.Before(entry.expiresAt) {
			count++
		}
	}
	return count
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

		id := ip

		// Store raw Base64 OVPN config in runtime-only in-memory cache keyed by stable Node ID.
		// This secret NEVER reaches the database.
		SetOVPNSecret(id, b64Config)

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
