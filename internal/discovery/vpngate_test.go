package discovery

import (
	"strings"
	"testing"
)

func TestParseCSV(t *testing.T) {
	// A small dummy CSV representing VPN Gate response
	csvData := `*vpn_servers
#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
public-vpn-99,192.168.1.1,1000,10,10000000,Japan,JP,10,1234567,100,5000000,2,dummy,,base64datahere
public-vpn-100,192.168.1.2,500,20,5000000,Korea Republic of,KR,5,123456,50,2500000,2,dummy,,base64datahere2
`

	nodes, err := parseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(nodes) != 2 {
		t.Fatalf("Expected 2 nodes, got %d", len(nodes))
	}

	n1 := nodes[0]
	if n1.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", n1.IP)
	}
	if n1.Country != "JP" {
		t.Errorf("Expected Country JP, got %s", n1.Country)
	}
	if n1.Score != 1000 {
		t.Errorf("Expected Score 1000, got %d", n1.Score)
	}
}
