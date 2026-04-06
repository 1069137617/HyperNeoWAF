package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/waf-project/backend/internal/model"
	"github.com/waf-project/backend/internal/repository"
	"golang.org/x/net/publicsuffix"
	"gorm.io/gorm"
)

var (
	ErrLogNotFound = errors.New("log not found")
)

// LogService handles security log operations
type LogService struct {
	db          *gorm.DB
	redisClient repository.RedisClient
	maskingSvc  *MaskingService
}

// NewLogService creates a new LogService instance
func NewLogService(db *gorm.DB, redisClient repository.RedisClient) *LogService {
	return &LogService{
		db:          db,
		redisClient: redisClient,
		maskingSvc:  NewMaskingService(),
	}
}

// ReceiveLogsPayload represents batch log submission from OpenResty
type ReceiveLogsPayload struct {
	Source string                   `json:"source"`
	Count  int                      `json:"count"`
	Logs   []map[string]interface{} `json:"logs"`
}

// LogFilter represents filter options for log queries
type LogFilter struct {
	StartTime  *time.Time
	EndTime    *time.Time
	ClientIP   string
	Method     string
	WAFAction  string
	WAFRule    string
	StatusCode *int
	SearchTerm string
}

// ListLogsResponse represents paginated log list response
type ListLogsResponse struct {
	Data       []model.SecurityLog `json:"data"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}

// ReceiveLogs receives and processes security logs from OpenResty
func (s *LogService) ReceiveLogs(payload *ReceiveLogsPayload) error {
	if payload.Logs == nil || len(payload.Logs) == 0 {
		return nil
	}

	batchID := generateBatchID()
	now := time.Now()

	// Process each log entry
	for _, rawLog := range payload.Logs {
		logEntry := s.processRawLog(rawLog, payload.Source, batchID, now)

		if logEntry != nil {
			result := s.db.Create(logEntry)
			if result.Error != nil {
				logger.Error("Failed to insert log entry:", result.Error)
				continue
			}
		}
	}

	logger.Info(fmt.Sprintf("Received and processed %d logs from %s", len(payload.Logs), payload.Source))
	return nil
}

// processRawLog converts raw map to SecurityLog entity with secondary masking
func (s *LogService) processRawLog(rawLog map[string]interface{}, source, batchID string, processedAt time.Time) *model.SecurityLog {
	entry := &model.SecurityLog{
		Source:      source,
		BatchID:     batchID,
		ProcessedAt: &processedAt,
	}

	// Extract timestamp
	if ts, ok := rawLog["timestamp"].(float64); ok {
		entry.Timestamp = time.Unix(int64(ts), 0)
	} else if tsStr, ok := rawLog["timestamp_iso"].(string); ok {
		if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
			entry.Timestamp = t
		}
		entry.TimestampISO = tsStr
	}

	// Apply secondary masking to all fields (defense in depth)
	if ip, ok := rawLog["client_ip"].(string); ok {
		entry.ClientIP = s.maskingSvc.MaskField("ip", ip)
	}

	if method, ok := rawLog["method"].(string); ok {
		entry.Method = strings.ToUpper(method)
	}

	if uri, ok := rawLog["uri"].(string); ok {
		entry.URI = s.maskingSvc.MaskField("uri", uri)
	}

	if args, ok := rawLog["args"].(string); ok {
		entry.Args = s.maskingSvc.MaskField("args", args)
	}

	if status, ok := rawLog["status_code"].(float64); ok {
		entry.StatusCode = int(status)
	}

	if action, ok := rawLog["waf_action"].(string); ok {
		entry.WAFAction = action
	}

	if rule, ok := rawLog["waf_rule"].(string); ok {
		entry.WAFRule = rule
	}

	if reason, ok := rawLog["waf_reason"].(string); ok {
		entry.WAFReason = reason
	}

	if rt, ok := rawLog["request_time"].(float64); ok {
		entry.RequestTime = rt
	}

	if bs, ok := rawLog["bytes_sent"].(float64); ok {
		entry.BytesSent = int64(bs)
	}

	if bbs, ok := rawLog["body_bytes_sent"].(float64); ok {
		entry.BodyBytesSent = int64(bbs)
	}

	// Process headers with masking
	if headers, ok := rawLog["headers"].(map[string]interface{}); ok {
		maskedHeaders := make(map[string]string)
		for k, v := range headers {
			if strVal, ok := v.(string); ok {
				maskedHeaders[k] = s.maskingSvc.MaskField(k, strVal)
			}
		}
		headersJSON, _ := json.Marshal(maskedHeaders)
		entry.HeadersJSON = string(headersJSON)
	}

	// Process body if present (with extra masking)
	if body, ok := rawLog["body"]; ok {
		bodyJSON, _ := json.Marshal(s.maskingSvc.MaskTable(body))
		entry.BodyJSON = string(bodyJSON)
	}

	return entry
}

// ListLogs retrieves paginated security logs with filtering
func (s *LogService) ListLogs(filter *LogFilter, page, pageSize int) (*ListLogsResponse, error) {
	query := s.db.Model(&model.SecurityLog{})

	applyLogFilters(query, filter)

	// Count total
	var total int64
	query.Count(&total)

	// Paginate
	offset := (page - 1) * pageSize
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	var logs []model.SecurityLog
	result := query.Order("id DESC").Offset(offset).Limit(pageSize).Find(&logs)
	if result.Error != nil {
		return nil, result.Error
	}

	return &ListLogsResponse{
		Data:       logs,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ExportLogs exports logs as CSV or JSON format
func (s *LogService) ExportLogs(format string, filter *LogFilter) ([]byte, error) {
	// For export, we may want more records than usual
	pageSize := 10000
	response, err := s.ListLogs(filter, 1, pageSize)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(format) {
	case "csv":
		return s.convertToCSV(response.Data)
	case "json":
		return json.MarshalIndent(response.Data, "", "  ")
	default:
		return json.MarshalIndent(response.Data, "", "  ")
	}
}

// convertToCSV converts logs to CSV format
func (s *LogService) convertToCSV(logs []model.SecurityLog) ([]byte, error) {
	var builder strings.Builder

	// Header row
	builder.WriteString("ID,Timestamp,Client IP,Method,URI,Status Code,WAF Action,WAF Rule,Request Time\n")

	// Data rows
	for _, log := range logs {
		builder.WriteString(fmt.Sprintf("%d,%s,%s,%s,%s,%d,%s,%s,%.4f\n",
			log.ID,
			log.Timestamp.Format(time.RFC3339),
			log.ClientIP,
			log.Method,
			truncateString(log.URI, 200),
			log.StatusCode,
			log.WAFAction,
			truncateString(log.WAFRule, 100),
			log.RequestTime,
		))
	}

	return []byte(builder.String()), nil
}

// applyLogFilters applies filter conditions to query
func applyLogFilters(query *gorm.DB, filter *LogFilter) {
	if filter == nil {
		return
	}

	if filter.StartTime != nil {
		query = query.Where("timestamp >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("timestamp <= ?", *filter.EndTime)
	}
	if filter.ClientIP != "" {
		query = query.Where("client_ip LIKE ?", "%"+filter.ClientIP+"%")
	}
	if filter.Method != "" {
		query = query.Where("method = ?", strings.ToUpper(filter.Method))
	}
	if filter.WAFAction != "" {
		query = query.Where("waf_action = ?", filter.WAFAction)
	}
	if filter.WAFRule != "" {
		query = query.Where("waf_rule LIKE ?", "%"+filter.WAFRule+"%")
	}
	if filter.StatusCode != nil {
		query = query.Where("status_code = ?", *filter.StatusCode)
	}
	if filter.SearchTerm != "" {
		searchPattern := "%" + filter.SearchTerm + "%"
		query = query.Where(
			"client_ip LIKE ? OR uri LIKE ? OR waf_reason LIKE ? OR waf_rule LIKE ?",
			searchPattern, searchPattern, searchPattern, searchPattern,
		)
	}
}

// GetLogStats returns aggregate statistics about logs
func (s *LogService) GetLogStats(timeRange string) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	now := time.Now()
	var startTime time.Time

	switch timeRange {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	// Total requests
	var totalRequests int64
	s.db.Model(&model.SecurityLog{}).Where("timestamp >= ?", startTime).Count(&totalRequests)
	stats["total_requests"] = totalRequests

	// Blocked/denied requests
	var blockedRequests int64
	s.db.Model(&model.SecurityLog{}).
		Where("timestamp >= ? AND waf_action = ?", startTime, model.WAFActions.Deny).
		Count(&blockedRequests)
	stats["blocked_requests"] = blockedRequests

	// Rate limited requests
	var rateLimitedRequests int64
	s.db.Model(&model.SecurityLog{}).
		Where("timestamp >= ? AND waf_action = ?", startTime, model.WAFActions.RateLimited).
		Count(&rateLimitedRequests)
	stats["rate_limited_requests"] = rateLimitedRequests

	// Block rate calculation
	if totalRequests > 0 {
		blockRate := float64(blockedRequests+rateLimitedRequests) / float64(totalRequests) * 100
		stats["block_rate"] = blockRate
	} else {
		stats["block_rate"] = 0.0
	}

	// Top attacked URLs
	type URLStat struct {
		URL   string `json:"url"`
		Count int64  `json:"count"`
	}
	var topURLs []URLStat
	s.db.Model(&model.SecurityLog{}).
		Select("uri as url, COUNT(*) as count").
		Where("timestamp >= ? AND waf_action IN (?)", startTime, []string{model.WAFActions.Deny, model.WAFActions.RateLimited}).
		Group("uri").
		Order("count DESC").
		Limit(10).
		Find(&topURLs)
	stats["top_attacked_urls"] = topURLs

	// Attack type distribution
	type AttackStat struct {
		Rule  string `json:"rule"`
		Count int64  `json:"count"`
	}
	var attackStats []AttackStat
	s.db.Model(&model.SecurityLog{}).
		Select("waf_rule as rule, COUNT(*) as count").
		Where("timestamp >= ? AND waf_action = ?", startTime, model.WAFActions.Deny).
		Group("waf_rule").
		Order("count DESC").
		Limit(10).
		Find(&attackStats)
	stats["attack_type_distribution"] = attackStats

	return stats, nil
}

func generateBatchID() string {
	return fmt.Sprintf("batch_%d_%d", time.Now().UnixNano(), time.Now().UnixMicro())
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
