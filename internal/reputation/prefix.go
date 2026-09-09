package reputation

import (
	"fmt"
	"net"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AnalyzePrefix extracts the /24 CIDR prefix for IPv4 addresses.
func AnalyzePrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

// RecordPrefixSample records an IP's reputation into the prefix intelligence table.
func RecordPrefixSample(db *gorm.DB, ipStr string, score int, isBad bool, isHardReject bool) error {
	if db == nil {
		return nil
	}
	prefix := AnalyzePrefix(ipStr)
	if prefix == "" {
		return nil
	}

	var entry models.PrefixIntelligence
	err := db.Where("prefix = ?", prefix).First(&entry).Error
	if err != nil {
		// Create new record
		badCount := 0
		if isBad {
			badCount = 1
		}
		rejectCount := 0
		if isHardReject {
			rejectCount = 1
		}
		newEntry := models.PrefixIntelligence{
			Prefix:          prefix,
			SampleCount:     1,
			BadCount:        badCount,
			HardRejectCount: rejectCount,
			AverageScore:    float64(score),
			LastSeen:        time.Now(),
		}
		return db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "prefix"}},
			DoUpdates: clause.AssignmentColumns([]string{"sample_count", "bad_count", "hard_reject_count", "average_score", "last_seen"}),
		}).Create(&newEntry).Error
	}

	// Update existing record
	entry.SampleCount++
	if isBad {
		entry.BadCount++
	}
	if isHardReject {
		entry.HardRejectCount++
	}
	entry.AverageScore = (entry.AverageScore*float64(entry.SampleCount-1) + float64(score)) / float64(entry.SampleCount)
	entry.LastSeen = time.Now()

	return db.Save(&entry).Error
}

// EvaluatePrefixRisk evaluates whether a CIDR prefix is high-risk.
// To avoid false positives, a prefix is only penalized if it meets or exceeds the badLimit threshold.
func EvaluatePrefixRisk(db *gorm.DB, ipStr string, badLimit int) (isHighRisk bool, penalty int, explanation string) {
	if db == nil {
		return false, 0, ""
	}
	prefix := AnalyzePrefix(ipStr)
	if prefix == "" {
		return false, 0, ""
	}

	var entry models.PrefixIntelligence
	if err := db.Where("prefix = ?", prefix).First(&entry).Error; err != nil {
		return false, 0, "no prior prefix data"
	}

	if badLimit <= 0 {
		badLimit = 3
	}

	if entry.BadCount >= badLimit || entry.HardRejectCount >= 2 {
		penalty = 20
		return true, penalty, fmt.Sprintf("Prefix %s has %d bad / %d hard-reject samples out of %d total (threshold >= %d)",
			prefix, entry.BadCount, entry.HardRejectCount, entry.SampleCount, badLimit)
	}

	return false, 0, fmt.Sprintf("Prefix %s normal (%d bad / %d total, below threshold %d)",
		prefix, entry.BadCount, entry.SampleCount, badLimit)
}
