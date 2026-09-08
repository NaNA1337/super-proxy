package reputation

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Result defines the outcome of a reputation check
type Result struct {
	IP             string
	HardReject     bool
	ScorePenalty   int
	ProviderReason string
}

// Provider represents a reputation API provider (AbuseIPDB, GreyNoise, etc.)
type Provider interface {
	CheckIP(ctx context.Context, ip string) (*Result, error)
	Name() string
}

type Engine struct {
	providers []Provider
}

func NewEngine() *Engine {
	return &Engine{
		providers: []Provider{
			// We can initialize Dummy/Mock providers here. 
			// Real ones will require API keys from config.
			&DummyProvider{},
		},
	}
}

// AddProvider registers a new reputation provider
func (e *Engine) AddProvider(p Provider) {
	e.providers = append(e.providers, p)
}

// EvaluateIP runs the IP against all enabled providers
func (e *Engine) EvaluateIP(ctx context.Context, ip string) (*Result, error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var finalResult = &Result{IP: ip}
	var errors []string

	for _, p := range e.providers {
		wg.Add(1)
		go func(provider Provider) {
			defer wg.Done()
			res, err := provider.CheckIP(ctx, ip)
			
			mu.Lock()
			defer mu.Unlock()
			
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", provider.Name(), err))
				return
			}

			if res.HardReject {
				finalResult.HardReject = true
				finalResult.ProviderReason += fmt.Sprintf("[%s: HARD REJECT - %s] ", provider.Name(), res.ProviderReason)
			}
			finalResult.ScorePenalty += res.ScorePenalty
			if res.ScorePenalty > 0 && !res.HardReject {
				finalResult.ProviderReason += fmt.Sprintf("[%s: SOFT PENALTY (-%d) - %s] ", provider.Name(), res.ScorePenalty, res.ProviderReason)
			}
		}(p)
	}

	wg.Wait()

	if len(errors) == len(e.providers) && len(e.providers) > 0 {
		return nil, fmt.Errorf("all reputation providers failed: %v", errors)
	}

	return finalResult, nil
}

// AnalyzePrefix determines the /24 CIDR block of an IP
func AnalyzePrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return "" // Focus on IPv4 for now
	}
	
	// Return /24 prefix (e.g. 219.100.37.0)
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

// DummyProvider is a stub for testing
type DummyProvider struct{}

func (d *DummyProvider) Name() string {
	return "DummyAbuseIPDB"
}

func (d *DummyProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	// Fake logic: if IP ends with .66, hard reject
	if strings.HasSuffix(ip, ".66") {
		return &Result{
			IP:             ip,
			HardReject:     true,
			ScorePenalty:   1000,
			ProviderReason: "recent high confidence attack detected",
		}, nil
	}
	return &Result{
		IP:             ip,
		HardReject:     false,
		ScorePenalty:   0,
		ProviderReason: "clean",
	}, nil
}
