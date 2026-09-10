package reputation

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EngineConfig struct {
	FailurePolicy  string        // "conservative" (default) or "lenient"
	CacheTTL       time.Duration // default 24h
	LenientPenalty int           // soft penalty when unknown under lenient mode (default: 20)
}

type Engine struct {
	providers      []Provider
	cache          *Cache
	failurePolicy  string
	lenientPenalty int
	db             *gorm.DB
	mu             sync.RWMutex
}

func NewEngine() *Engine {
	return NewEngineWithConfig(EngineConfig{
		FailurePolicy:  "conservative",
		CacheTTL:       24 * time.Hour,
		LenientPenalty: 20,
	})
}

func NewEngineWithConfig(cfg EngineConfig) *Engine {
	if cfg.FailurePolicy == "" {
		cfg.FailurePolicy = "conservative"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 24 * time.Hour
	}
	if cfg.LenientPenalty <= 0 {
		cfg.LenientPenalty = 20
	}
	return &Engine{
		providers:      []Provider{},
		cache:          NewCache(cfg.CacheTTL),
		failurePolicy:  cfg.FailurePolicy,
		lenientPenalty: cfg.LenientPenalty,
	}
}

// SetDB attaches the database connection for persisting provider evidence,
// network intelligence, and ASN observations.
func (e *Engine) SetDB(db *gorm.DB) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.db = db
}

// AddProvider registers a new reputation provider.
func (e *Engine) AddProvider(p Provider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.providers = append(e.providers, p)
}

// FailurePolicy returns the configured reputation failure policy ("conservative" or "lenient").
func (e *Engine) FailurePolicy() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.failurePolicy
}

// GetCache returns the internal TTL cache.
func (e *Engine) GetCache() *Cache {
	return e.cache
}

// EvaluateIP runs the IP against cache and all registered providers in parallel,
// preserves raw provider evidence, and persists audit logs to the database.
func (e *Engine) EvaluateIP(ctx context.Context, ip string) (*Result, error) {
	// 1. Check aggregate cache first
	if cached, hit := e.cache.Get(ip); hit {
		log.Printf("[Reputation] Aggregate cache HIT for %s: Status=%s, Penalty=%d, HardReject=%v",
			ip, cached.Status, cached.ScorePenalty, cached.HardReject)
		return cached, nil
	}

	e.mu.RLock()
	providers := make([]Provider, len(e.providers))
	copy(providers, e.providers)
	db := e.db
	policy := e.failurePolicy
	lenientPenalty := e.lenientPenalty
	e.mu.RUnlock()

	if len(providers) == 0 {
		unknownRes := &Result{
			IP:             ip,
			Status:         StatusUnknown,
			ProviderReason: "UNKNOWN (No reputation providers configured)",
		}
		return unknownRes, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	finalResult := &Result{
		IP:        ip,
		Status:    StatusGood, // default if all succeed cleanly; adjusted if penalties or unknown
		Evidences: []ReputationResult{},
	}
	var errMessages []string
	unknownCount := 0
	successCount := 0

	for _, p := range providers {
		wg.Add(1)
		go func(provider Provider) {
			defer wg.Done()

			// Check per-provider TTL cache
			if cachedProv, hit := e.cache.GetProvider(ip, provider.Name()); hit {
				mu.Lock()
				defer mu.Unlock()
				successCount++
				finalResult.Evidences = append(finalResult.Evidences, *cachedProv)
				e.mergeProviderResult(finalResult, cachedProv, &unknownCount)
				return
			}

			// Query provider with timeout
			provCtx, provCancel := context.WithTimeout(ctx, 8*time.Second)
			defer provCancel()

			res, err := provider.CheckIP(provCtx, ip)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errMessages = append(errMessages, fmt.Sprintf("%s: %v", provider.Name(), err))
				unknownCount++
				failedRes := ReputationResult{
					Provider:       provider.Name(),
					IP:             ip,
					Status:         StatusUnknown,
					ObservedAt:     time.Now(),
					Error:          err.Error(),
					ProviderReason: fmt.Sprintf("%s query error: %v", provider.Name(), err),
				}
				finalResult.Evidences = append(finalResult.Evidences, failedRes)
				e.persistEvidence(db, failedRes)
				return
			}

			successCount++
			if res == nil {
				res = &ReputationResult{
					Provider:   provider.Name(),
					IP:         ip,
					Status:     StatusUnknown,
					ObservedAt: time.Now(),
				}
			}

			// Store in per-provider cache
			e.cache.SetProvider(ip, provider.Name(), res)

			// Append to evidences and persist
			finalResult.Evidences = append(finalResult.Evidences, *res)
			e.persistEvidence(db, *res)

			// Merge into aggregate result
			e.mergeProviderResult(finalResult, res, &unknownCount)
		}(p)
	}

	wg.Wait()

	// If all providers failed or timed out:
	if successCount == 0 {
		finalResult.Status = StatusUnknown
		finalResult.ProviderReason = fmt.Sprintf("UNKNOWN: all providers failed (%v)", errMessages)
		if policy == "lenient" {
			finalResult.ScorePenalty += lenientPenalty
			finalResult.ProviderReason += fmt.Sprintf(" [Policy: lenient UNKNOWN applied penalty -%d]", lenientPenalty)
		}
		log.Printf("[Reputation] IP %s reputation check UNKNOWN: %s", ip, finalResult.ProviderReason)
		return finalResult, nil
	}

	// Policy handling for UNKNOWN evaluations
	if unknownCount > 0 && !finalResult.HardReject {
		if policy == "conservative" {
			finalResult.Status = StatusUnknown
			finalResult.ProviderReason += " [Policy: conservative UNKNOWN fail-closed]"
		} else if policy == "lenient" {
			finalResult.ScorePenalty += lenientPenalty
			finalResult.ProviderReason += fmt.Sprintf(" [Policy: lenient UNKNOWN applied penalty -%d]", lenientPenalty)
		}
	}

	// Persist consolidated NetworkIntelligence and ASNObservation to DB
	e.persistNetworkAndASN(db, finalResult)

	// Store in aggregate cache
	e.cache.Set(ip, finalResult)

	return finalResult, nil
}

func (e *Engine) mergeProviderResult(finalResult *Result, res *ReputationResult, unknownCount *int) {
	// Track Network Intelligence
	asn := res.NetworkInfo.ASN
	if asn == "" {
		asn = res.ASN
	}
	if asn != "" {
		finalResult.NetworkInfo.ASN = asn
	}

	isp := res.NetworkInfo.ISP
	if isp == "" {
		isp = res.ISP
	}
	if isp != "" {
		finalResult.NetworkInfo.ISP = isp
	}

	org := res.NetworkInfo.Organization
	if org == "" {
		org = res.Organization
	}
	if org != "" {
		finalResult.NetworkInfo.Organization = org
	}

	if res.NetworkInfo.NetworkType != "" {
		finalResult.NetworkInfo.NetworkType = res.NetworkInfo.NetworkType
	}
	if res.NetworkInfo.IsVPN || (res.IsVPN != nil && *res.IsVPN) {
		finalResult.NetworkInfo.IsVPN = true
	}
	if res.NetworkInfo.IsProxy || (res.IsProxy != nil && *res.IsProxy) {
		finalResult.NetworkInfo.IsProxy = true
	}
	if res.NetworkInfo.IsTor || (res.IsTor != nil && *res.IsTor) {
		finalResult.NetworkInfo.IsTor = true
	}
	if res.NetworkInfo.IsHosting || (res.IsHosting != nil && *res.IsHosting) {
		finalResult.NetworkInfo.IsHosting = true
	}

	// Handle Status & Penalties
	if res.Status == StatusUnknown {
		*unknownCount++
		finalResult.ProviderReason += fmt.Sprintf("[%s: UNKNOWN - %s] ", res.Provider, res.ProviderReason)
	} else if res.HardReject || res.Status == StatusBad {
		finalResult.Status = StatusBad
		if res.HardReject {
			finalResult.HardReject = true
			finalResult.ProviderReason += fmt.Sprintf("[%s: HARD REJECT - %s] ", res.Provider, res.ProviderReason)
		} else {
			finalResult.ProviderReason += fmt.Sprintf("[%s: BAD - %s] ", res.Provider, res.ProviderReason)
		}
	} else if res.Status == StatusRisky || res.ScorePenalty > 0 || res.NetworkInfo.IsVPN || res.NetworkInfo.IsHosting || res.NetworkInfo.IsProxy {
		// Network traits (VPN/Hosting/Proxy) and score penalties represent elevated risk, NOT malicious intent!
		if finalResult.Status != StatusBad {
			finalResult.Status = StatusRisky
		}
		finalResult.ScorePenalty += res.ScorePenalty
		if res.ScorePenalty > 0 {
			finalResult.ProviderReason += fmt.Sprintf("[%s: RISKY/PENALTY (-%d) - %s] ", res.Provider, res.ScorePenalty, res.ProviderReason)
		} else {
			finalResult.ProviderReason += fmt.Sprintf("[%s: RISKY - %s] ", res.Provider, res.ProviderReason)
		}
	} else {
		finalResult.ProviderReason += fmt.Sprintf("[%s: %s] ", res.Provider, res.ProviderReason)
	}
}

func (e *Engine) persistEvidence(db *gorm.DB, res ReputationResult) {
	if db == nil {
		return
	}

	scoreVal := 0.0
	if res.Score != nil {
		scoreVal = *res.Score
	}
	abuseConfVal := 0
	if res.AbuseConfidence != nil {
		abuseConfVal = int(*res.AbuseConfidence)
	}
	fraudScoreVal := 0
	if res.FraudScore != nil {
		fraudScoreVal = int(*res.FraudScore)
	}
	reportsVal := 0
	if res.Reports != nil {
		reportsVal = *res.Reports
	}

	isVPN := res.NetworkInfo.IsVPN
	if res.IsVPN != nil {
		isVPN = *res.IsVPN
	}
	isProxy := res.NetworkInfo.IsProxy
	if res.IsProxy != nil {
		isProxy = *res.IsProxy
	}
	isTor := res.NetworkInfo.IsTor
	if res.IsTor != nil {
		isTor = *res.IsTor
	}
	isHosting := res.NetworkInfo.IsHosting
	if res.IsHosting != nil {
		isHosting = *res.IsHosting
	}
	isRes := false
	if res.IsResidential != nil {
		isRes = *res.IsResidential
	}

	obs := models.ReputationEvidence{
		IP:              res.IP,
		Provider:        res.Provider,
		Status:          string(res.Status),
		Score:           scoreVal,
		AbuseConfidence: abuseConfVal,
		FraudScore:      fraudScoreVal,
		IsVPN:           isVPN,
		IsProxy:         isProxy,
		IsTor:           isTor,
		IsHosting:       isHosting,
		IsResidential:   isRes,
		ASN:             res.ASN,
		ISP:             res.ISP,
		Organization:    res.Organization,
		CountryCode:     res.CountryCode,
		Reports:         reportsVal,
		RawCategory:     res.RawCategory,
		ObservedAt:      res.ObservedAt,
		Error:           res.Error,
	}

	if err := db.Create(&obs).Error; err != nil {
		log.Printf("[Reputation] Warning: failed to persist evidence for %s (%s): %v", res.IP, res.Provider, err)
	}
}

func (e *Engine) persistNetworkAndASN(db *gorm.DB, finalResult *Result) {
	if db == nil || finalResult == nil {
		return
	}

	netIntel := models.NetworkIntelligence{
		IP:            finalResult.IP,
		ASN:           finalResult.NetworkInfo.ASN,
		ISP:           finalResult.NetworkInfo.ISP,
		Organization:  finalResult.NetworkInfo.Organization,
		IsHosting:     finalResult.NetworkInfo.IsHosting,
		IsVPN:         finalResult.NetworkInfo.IsVPN,
		IsProxy:       finalResult.NetworkInfo.IsProxy,
		IsTor:         finalResult.NetworkInfo.IsTor,
		Source:        "reputation_evaluation",
		ObservedAt:    time.Now(),
	}

	_ = db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "ip"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"asn", "isp", "organization", "is_hosting", "is_vpn", "is_proxy", "is_tor", "observed_at",
		}),
	}).Create(&netIntel).Error

	if finalResult.NetworkInfo.ASN != "" {
		asnObs := models.ASNObservation{
			ASN:          finalResult.NetworkInfo.ASN,
			ISP:          finalResult.NetworkInfo.ISP,
			Organization: finalResult.NetworkInfo.Organization,
			IP:           finalResult.IP,
			IsBad:        finalResult.Status == StatusBad,
			IsHardReject: finalResult.HardReject,
			IsUnknown:    finalResult.Status == StatusUnknown,
			Score:        finalResult.ScorePenalty,
			ObservedAt:   time.Now(),
		}
		_ = db.Create(&asnObs).Error
	}
}
