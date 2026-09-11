// init-config writes a new deployment configuration with stable credentials.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/NaNA1337/super-proxy/internal/xray"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func main() {
	managementOnly := flag.Bool("management-only", false, "initialize API-only configuration without public VLESS")
	address := flag.String("address", "", "public IPv4 address or DNS name clients connect to")
	output := flag.String("output", "config.yaml", "new YAML file (existing files are never overwritten)")
	listen := flag.String("api-listen", "127.0.0.1", "Agent HTTPS bind address")
	flag.Parse()
	if err := xray.ValidatePublicAddress(*address); err != nil && !*managementOnly {
		log.Fatal(err)
	}
	private, public, err := xray.GenerateX25519Keypair()
	if err != nil {
		log.Fatal(err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		log.Fatal(err)
	}
	absolute, err := filepath.Abs(*output)
	if err != nil {
		log.Fatal(err)
	}
	dir := filepath.Dir(absolute)
	cfg := map[string]any{
		"region":     map[string]any{"primary": "JP", "fallback": []string{"KR", "SG"}},
		"database":   map[string]any{"path": filepath.Join(dir, "manager.db")},
		"discovery":  map[string]any{"url": "https://www.vpngate.net/api/iphone/", "interval": 15},
		"reputation": map[string]any{"enabled": false, "failure_policy": "conservative"},
		"api":        map[string]any{"listen": *listen, "port": 60000, "key": hex.EncodeToString(token)},
		"xray": map[string]any{"config_path": filepath.Join(dir, "xray_config.json"), "vless": map[string]any{
			"enabled": !*managementOnly, "public_address": *address, "listen": "0.0.0.0", "port": 443,
			"uuid": uuid.NewString(), "private_key": private, "public_key": public, "short_ids": []string{xray.GenerateShortID()},
			"flow": xray.DefaultFlow, "dest": xray.DefaultRealityTarget, "server_names": []string{xray.DefaultRealitySNI},
			"fingerprint": xray.DefaultRealityFP, "outbound_only_443": true,
		}},
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal(err)
	}
	f, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatal(err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		log.Fatal(writeErr)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
	fmt.Printf("Created %s (0600). Keep this file: it contains the API token and stable Reality credentials.\n", absolute)
}
