package service

import (
	"encoding/json"
	"time"

	"github.com/waf-project/backend/internal/model"
	"gorm.io/gorm"
)

// DashboardService provides aggregated statistics for dashboard display
type DashboardService struct {
	db *gorm.DB
}

// NewDashboardService creates a new DashboardService instance
func NewDashboardService(db *gorm.DB) *DashboardService {
	return &DashboardService{db: db}
}

// StatsResponse represents overall dashboard statistics
type StatsResponse struct {
	TotalRequests    int64   `json:"total_requests"`
	BlockedRequests  int64   `json:"blocked_requests"`
	RateLimitedReqs  int64   `json:"rate_limited_requests"`
	QPS              float64 `json:"qps"`               // Queries per second (current)
	BlockRate        float64 `json:"block_rate"`         // Percentage
	ActiveRules      int64   `json:"active_rules"`
	BlacklistedIPs   int64   `json:"blacklisted_ips"`
	WhitelistedIPs   int64   `json:"whitelisted_ips"`
	UptimeSeconds    int64   `json:"uptime_seconds"`
	LastLogTimestamp *time.Time `json:"last_log_timestamp,omitempty"`
}

// TrendDataPoint represents a single data point for trend charts
type TrendDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label"`
}

// TrendsResponse contains trend data for various metrics
type TrendsResponse struct {
	TimeRange string            `json:"time_range"`
	Requests  []TrendDataPoint `json:"requests"`
	Blocked   []TrendDataPoint `json:"blocked"`
	QPS       []TrendDataPoint `json:"qps"`
}

// RecentEvent represents a recent security event for dashboard display
type RecentEvent struct {
	ID           uint      `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	URI          string    `json:"uri"`
	StatusCode   int       `json:"status_code"`
	WAFAction    string    `json:"waf_action"`
	WAFRule      string    `json:"waf_rule"`
	WAFReason    string    `json:"waf_reason"`
	RequestTime  float64   `json:"request_time"`
}

// TopAttackStat represents attack statistics grouped by rule/type
type TopAttackStat struct {
	RuleName string `json:"rule_name"`
	Count    int64  `json:"count"`
	Percentage float64 `json:"percentage"`
}

// GetDashboardStats returns overall system statistics
func (s *DashboardService) GetDashboardStats() (*StatsResponse, error) {
	stats := &StatsResponse{}

	now := time.Now()
	last24h := now.Add(-24 * time.Hour)

	// Total requests in last 24h
	s.db.Model(&model.SecurityLog{}).
		Where("timestamp >= ?", last24h).
		Count(&stats.TotalRequests)

	// Blocked requests (deny action)
	s.db.Model(&model.SecurityLog{}).
		Where("timestamp >= ? AND waf_action = ?", last24h, model.WAFActions.Deny).
		Count(&stats.BlockedRequests)

	// Rate limited requests
	s.db.Model(&model.SecurityLog{}).
		Where("timestamp >= ? AND waf_action = ?", last24h, model.WAFActions.RateLimited).
		Count(&stats.RateLimitedReqs)

	// Calculate block rate
	if stats.TotalRequests > 0 {
		stats.BlockRate = float64(stats.BlockedRequests+stats.RateLimitedReqs) / float64(stats.TotalRequests) * 100
	}

	// Active rules count
	s.db.Model(&model.Rule{}).Where("enabled = ?", true).Count(&stats.ActiveRules)

	// Blacklist count
	s.db.Model(&model.IPListEntry{}).
		Where("type = ? AND is_active = ? AND (expires_at IS NULL OR expires_at > NOW())",
			model.IPListTypes.Blacklist, true).
		Count(&stats.BlacklistedIPs)

	// Whitelist count
	s.db.Model(&model.IPListEntry{}).
		Where("type = ? AND is_active = ? AND (expires_at IS NULL OR expires_at > NOW())",
			model.IPListTypes.Whitelist, true).
		Count(&stats.WhitelistedIPs)

	// Current QPS (requests in last minute / 60)
	last1min := now.Add(-1 * time.Minute)
	var recentRequests int64
	s.db.Model(&model.SecurityLog{}).Where("timestamp >= ?", last1min).Count(&recentRequests)
	stats.QPS = float64(recentRequests) / 60.0

	// Last log timestamp
	var latestLog model.SecurityLog
	s.db.Order("timestamp DESC").First(&latestLog)
	if latestLog.ID > 0 {
		stats.LastLogTimestamp = &latestLog.Timestamp
	}

	// Uptime (placeholder - would need actual process start time)
	stats.UptimeSeconds = int64(time.Since(now).Seconds()) // Placeholder

	return stats, nil
}

// GetTrends returns trend data for the specified time range
func (s *DashboardService) GetTrends(timeRange string) (*TrendsResponse, error) {
	response := &TrendsResponse{TimeRange: timeRange}

	now := time.Now()
	var startTime time.Time
	var intervalMinutes int

	switch timeRange {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
		intervalMinutes = 5 // 5-minute intervals
	case "6h":
		startTime = now.Add(-6 * time.Hour)
		intervalMinutes = 30
	case "24h":
		startTime = now.Add(-24 * time.Hour)
		intervalMinutes = 60 // hourly
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
		intervalMinutes = 360 // 6-hourly
	default:
		startTime = now.Add(-24 * time.Hour)
		intervalMinutes = 60
	}

	// Generate trend data points
	numPoints := int(now.Sub(startTime).Minutes()) / intervalMinutes
	if numPoints < 1 {
		numPoints = 1
	}

	for i := 0; i <= numPoints; i++ {
		pointStart := startTime.Add(time.Duration(i*intervalMinutes) * time.Minute)
		pointEnd := pointStart.Add(time.Duration(intervalMinutes) * time.Minute)
		if pointEnd.After(now) {
			pointEnd = now
		}

		var totalReq, blockedReq int64

		s.db.Model(&model.SecurityLog{}).
			Where("timestamp >= ? AND timestamp < ?", pointStart, pointEnd).
			Count(&totalReq)

		s.db.Model(&model.SecurityLog{}).
			Where("timestamp >= ? AND timestamp < ? AND waf_action IN (?)",
				pointStart, pointEnd, []string{model.WAFActions.Deny, model.WAFActions.RateLimited}).
			Count(&blockedReq)

		qps := 0.0
		durationMin := pointEnd.Sub(pointStart).Minutes()
		if durationMin > 0 {
			qps = float64(totalReq) / (durationMin * 60)
		}

		response.Requests = append(response.Requests, TrendDataPoint{
			Timestamp: pointStart,
			Value:     float64(totalReq),
			Label:     pointStart.Format("15:04"),
		})

		response.Blocked = append(response.Blocked, TrendDataPoint{
			Timestamp: pointStart,
			Value:     float64(blockedReq),
			Label:     pointStart.Format("15:04"),
		})

		response.QPS = append(response.QPS, TrendDataPoint{
			Timestamp: pointStart,
			Value:     qps,
			Label:     pointStart.Format("15:04"),
		})
	}

	return response, nil
}

// GetRecentEvents returns the most recent security events
func (s *DashboardService) GetRecentEvents(limit int) ([]RecentEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var logs []model.SecurityLog
	result := s.db.
		Select("id, timestamp, client_ip, method, uri, status_code, waf_action, waf_rule, waf_reason, request_time").
		Order("id DESC").
		Limit(limit).
		Find(&logs)

	if result.Error != nil {
		return nil, result.Error
	}

	events := make([]RecentEvent, len(logs))
	for i, log := range logs {
		events[i] = RecentEvent{
			ID:          log.ID,
			Timestamp:   log.Timestamp,
			ClientIP:    log.ClientIP,
			Method:      log.Method,
			URI:         truncateString(log.URI, 150),
			StatusCode:  log.StatusCode,
			WAFAction:   log.WAFAction,
			WAFRule:     log.WAFRule,
			WAFReason:   log.WAFReason,
			RequestTime: log.RequestTime,
		}
	}

	return events, nil
}

// GetTopAttacks returns top attack types by frequency
func (s *DashboardService) GetTopAttacks(limit int) ([]TopAttackStat, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}

	now := time.Now()
	timeWindow := now.Add(-24 * time.Hour)

	type AttackCount struct {
		WAFRule string `json:"waf_rule"`
		Count   int64  `json:"count"`
	}

	var attackCounts []AttackCount
	s.db.Model(&model.SecurityLog{}).
		Select("waf_rule, COUNT(*) as count").
		Where("timestamp >= ? AND waf_action = ? AND waf_rule != ''",
			timeWindow, model.WAFActions.Deny).
		Group("waf_rule").
		Order("count DESC").
		Limit(limit).
		Find(&attackCounts)

	// Calculate total for percentage
	var totalBlocked int64
	s.db.Model(&model.SecurityLog{}).
		Where("timestamp >= ? AND waf_action = ?", timeWindow, model.WAFActions.Deny).
		Count(&totalBlocked)

	results := make([]TopAttackStat, len(attackCounts))
	for i, ac := range attackCounts {
		percentage := 0.0
		if totalBlocked > 0 {
			percentage = float64(ac.Count) / float64(totalBlocked) * 100
		}
		results[i] = TopAttackStat{
			RuleName:   ac.WAFRule,
			Count:      ac.Count,
			Percentage: percentage,
		}
	}

	return results, nil
}
