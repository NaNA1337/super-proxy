package discovery

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

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
		port := extractPortFromBase64(record[14])
		
		// Create a unique ID using IP and (extracted port if possible, though VPN Gate IP is usually unique enough)
		id := ip
		if port != "" {
			id = fmt.Sprintf("%s:%s", ip, port)
		}

		node := models.Node{
			ID:          id,
			HostName:    record[0],
			IP:          ip,
			Score:       score,
			Ping:        ping,
			Speed:       speed,
			CountryL:    record[5],
			Country:     record[6], // CountryShort
			Sessions:    sessions,
			Uptime:      uptime,
			Users:       users,
			Message:     record[13],
			OpenVPN:     record[14], // Base64 encoded
			Status:      "DISCOVERED",
			LastSeen:    now,
			FirstSeen:   now,
			FailCount:   0,
			HealthScore: 0,
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// extractPortFromBase64 tries to extract the port from the Base64 config
// This is a placeholder since we might not strictly need the port for the ID if IP is unique
func extractPortFromBase64(b64 string) string {
	// Full base64 decode and parse OpenVPN config could be implemented here
	// For Phase 1, we rely on IP as primary identifier or IP:HostName
	return ""
}
