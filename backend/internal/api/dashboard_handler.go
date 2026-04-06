package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/service"
)

// DashboardHandler handles dashboard and monitoring endpoints
type DashboardHandler struct {
	dashboardService *service.DashboardService
	logService       *service.LogService
}

// NewDashboardHandler creates a new DashboardHandler instance
func NewDashboardHandler(dashboardService *service.DashboardService, logService *service.LogService) *DashboardHandler {
	return &DashboardHandler{
		dashboardService: dashboardService,
		logService:       logService,
	}
}

// GetStats handles GET /api/v1/dashboard/stats
func (h *DashboardHandler) GetStats(c *gin.Context) {
	stats, err := h.dashboardService.GetDashboardStats()
	if err != nil {
		logger.Error("Failed to get dashboard stats:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve dashboard statistics",
			"code":    "DASHBOARD_STATS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetTrends handles GET /api/v1/dashboard/trends
func (h *DashboardHandler) GetTrends(c *gin.Context) {
	timeRange := c.DefaultQuery("range", "24h")

	trends, err := h.dashboardService.GetTrends(timeRange)
	if err != nil {
		logger.Error("Failed to get trends:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve trend data",
			"code":    "TRENDS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, trends)
}

// GetRecentEvents handles GET /api/v1/dashboard/recent-events
func (h *DashboardHandler) GetRecentEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if limit < 1 || limit > 100 {
		limit = 20
	}

	events, err := h.dashboardService.GetRecentEvents(limit)
	if err != nil {
		logger.Error("Failed to get recent events:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve recent events",
			"code":    "RECENT_EVENTS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": events})
}

// GetTopAttacks handles GET /api/v1/dashboard/top-attacks
func (h *DashboardHandler) GetTopAttacks(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	if limit < 1 || limit > 50 {
		limit = 10
	}

	topAttacks, err := h.dashboardService.GetTopAttacks(limit)
	if err != nil {
		logger.Error("Failed to get top attacks:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve attack statistics",
			"code":    "TOP_ATTACKS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": topAttacks})
}

// GetRealtimeQPS handles GET /api/v1/dashboard/qps (lightweight endpoint for polling)
func (h *DashboardHandler) GetRealtimeQPS(c *gin.Context) {
	stats, err := h.dashboardService.GetDashboardStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to get QPS data",
			"code":    "QPS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"qps":              stats.QPS,
		"total_requests":   stats.TotalRequests,
		"blocked_requests": stats.BlockedRequests,
		"rate_limited":     stats.RateLimitedReqs,
		"block_rate":       stats.BlockRate,
	})
}
