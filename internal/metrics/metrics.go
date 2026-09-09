package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ActiveSlots = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "active_slots",
		Help: "Current number of active egress slots",
	})
	StandbySlots = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "standby_slots",
		Help: "Current number of standby warm tunnels",
	})
	DrainingSlots = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "draining_slots",
		Help: "Current number of slots undergoing graceful draining",
	})

	TunnelUp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tunnel_up",
		Help: "Total count of successful tunnel connections established",
	})
	TunnelDown = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tunnel_down",
		Help: "Total count of tunnel disconnections or shutdowns",
	})

	TunnelConnectSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "tunnel_connect_seconds",
		Help:    "Time taken for OpenVPN tunnels to establish in seconds",
		Buckets: prometheus.DefBuckets,
	})

	TunnelRTT = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tunnel_rtt_ms",
		Help: "Round trip time in ms per interface",
	}, []string{"interface"})

	TunnelPacketLoss = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tunnel_packet_loss",
		Help: "Packet loss percentage per interface",
	}, []string{"interface"})

	TunnelThroughput = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tunnel_throughput",
		Help: "Download throughput in bits per second per interface",
	}, []string{"interface"})

	ReputationRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "reputation_requests",
		Help: "Total number of reputation evaluation requests",
	})
	ReputationFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "reputation_failures",
		Help: "Total number of reputation provider query failures",
	})
	ReputationCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "reputation_cache_hits",
		Help: "Total number of reputation TTL cache hits",
	})

	XrayRestarts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xray_restarts",
		Help: "Total number of Xray process restarts by supervisor",
	})
	XrayUptime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xray_uptime",
		Help: "Uptime seconds of currently running Xray process",
	})

	OpenVPNDCOActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openvpn_dco_active",
		Help: "Number of tunnels actively using Data Channel Offload (DCO)",
	})
	OpenVPNDCOFallback = promauto.NewCounter(prometheus.CounterOpts{
		Name: "openvpn_dco_fallback",
		Help: "Number of tunnels fallen back to userspace OpenVPN",
	})

	NodeFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "node_failures",
		Help: "Total number of node failure events",
	})
	NodeCooldowns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "node_cooldowns",
		Help: "Total number of nodes moved to cooldown",
	})
	NodeDead = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "node_dead",
		Help: "Total number of dead nodes (exceeded max retries)",
	})

	FallbackRegionUsage = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fallback_region_usage",
		Help: "Total number of times a fallback region node was chosen",
	})
)
