package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/service"
)

// LogHandler handles log-related endpoints
type LogHandler struct {
	logService *service.LogService
}

// NewLogHandler creates a new LogHandler instance
func NewLogHandler(logService *service.LogService) *LogHandler {
	return &LogHandler{logService: logService}
}

// ReceiveLogs handles POST /api/v1/logs/receive (called by OpenResty)
func (h *LogHandler) ReceiveLogs(c *gin.Context) {
	var payload service.ReceiveLogsPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body: " + err.Error(),
			"code":    "INVALID_PAYLOAD",
		})
		return
	}

	err := h.logService.ReceiveLogs(&payload)
	if err != nil {
		logger.Error("Failed to receive logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to process logs",
			"code":    "LOG_RECEIVE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Logs received successfully",
		"records_count": payload.Count,
	})
}

// ListLogs handles GET /api/v1/logs
func (h *LogHandler) ListLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	filter := &service.LogFilter{}

	// Parse time range
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = &t
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = &t
		}
	}

	// Parse other filters
	filter.ClientIP = c.Query("client_ip")
	filter.Method = strings.ToUpper(c.Query("method"))
	filter.WAFAction = c.Query("waf_action")
	filter.WAFRule = c.Query("waf_rule")
	filter.SearchTerm = c.Query("search")

	if statusCodeStr := c.Query("status_code"); statusCodeStr != "" {
		if code, err := strconv.Atoi(statusCodeStr); err == nil {
			statusCode := code
			filter.StatusCode = &statusCode
		}
	}

	response, err := h.logService.ListLogs(filter, page, pageSize)
	if err != nil {
		logger.Error("Failed to list logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve logs",
			"code":    "LOGS_LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetLogByID handles GET /api/v1/logs/:id
func (h *LogHandler) GetLogByID(c *gin.Context) {
	logID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid log ID",
			"code":    "INVALID_LOG_ID",
		})
		return
	}

	var logEntry model.SecurityLog
	result := db.First(&logEntry, logID)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Log entry not found",
			"code":    "LOG_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": logEntry})
}

// ExportLogs handles GET /api/v1/logs/export
func (h *LogHandler) ExportLogs(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	if !isValidExportFormat(format) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid format. Supported: csv, json",
			"code":    "INVALID_EXPORT_FORMAT",
		})
		return
	}

	filter := &service.LogFilter{}

	// Apply same filters as ListLogs
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = &t
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = &t
		}
	}
	filter.ClientIP = c.Query("client_ip")
	filter.SearchTerm = c.Query("search")

	data, err := h.logService.ExportLogs(format, filter)
	if err != nil {
		logger.Error("Failed to export logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to export logs",
			"code":    "LOG_EXPORT_FAILED",
		})
		return
	}

	contentType := "application/json"
	fileExt := ".json"

	if format == "csv" {
		contentType = "text/csv"
		fileExt = ".csv"
	}

	filename := fmt.Sprintf("waf-logs-export-%s%s", time.Now().Format("20060102-150405"), fileExt)

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, contentType, data)
}

// GetLogStats handles GET /api/v1/logs/stats
func (h *LogHandler) GetLogStats(c *gin.Context) {
	timeRange := c.DefaultQuery("range", "24h")

	stats, err := h.logService.GetLogStats(timeRange)
	if err != nil {
		logger.Error("Failed to get log stats:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve statistics",
			"code":    "LOG_STATS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func isValidExportFormat(format string) bool {
	return format == "json" || format == "csv"
}
