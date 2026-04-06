package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/service"
)

// IPListHandler handles IP blacklist/whitelist management endpoints
type IPListHandler struct {
	ipListService *service.IPListService
}

// NewIPListHandler creates a new IPListHandler instance
func NewIPListHandler(ipListService *service.IPListService) *IPListHandler {
	return &IPListHandler{ipListService: ipListService}
}

// ListIPs handles GET /api/v1/ip-list
func (h *IPListHandler) ListIPs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	ipType := c.Query("type") // blacklist or whitelist

	response, err := h.ipListService.ListIPs(ipType, page, pageSize)
	if err != nil {
		logger.Error("Failed to list IPs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve IP list",
			"code":    "IPLIST_LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// AddIP handles POST /api/v1/ip-list
func (h *IPListHandler) AddIP(c *gin.Context) {
	var req service.AddIPRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Validation failed: " + err.Error(),
			"code":    "VALIDATION_ERROR",
		})
		return
	}

	userID, _ := c.Get("user_id")
	entry, err := h.ipListService.AddIP(&req, userID.(uint))
	if err != nil {
		if err == service.ErrInvalidIPType {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Bad Request",
				"message": "Invalid IP type. Must be 'blacklist' or 'whitelist'",
				"code":    "INVALID_IP_TYPE",
			})
			return
		}
		if err == service.ErrIPAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{
				"error":   "Conflict",
				"message": "IP already exists in this list",
				"code":    "IP_ALREADY_EXISTS",
			})
			return
		}

		logger.Error("Failed to add IP:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to add IP entry",
			"code":    "IP_ADD_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "IP entry added successfully",
		"data":    entry,
	})
}

// GetIPByID handles GET /api/v1/ip-list/:id
func (h *IPListHandler) GetIPByID(c *gin.Context) {
	entryID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid IP entry ID",
			"code":    "INVALID_IP_ID",
		})
		return
	}

	entry, err := h.ipListService.GetIPByID(uint(entryID))
	if err != nil {
		if err == service.ErrIPNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Not Found",
				"message": "IP entry not found",
				"code":    "IP_ENTRY_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve IP entry",
			"code":    "IP_GET_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": entry})
}

// DeleteIP handles DELETE /api/v1/ip-list/:id
func (h *IPListHandler) DeleteIP(c *gin.Context) {
	entryID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid IP entry ID",
			"code":    "INVALID_IP_ID",
		})
		return
	}

	err = h.ipListService.DeleteIP(uint(entryID))
	if err != nil {
		if err == service.ErrIPNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Not Found",
				"message": "IP entry not found",
				"code":    "IP_ENTRY_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to delete IP entry",
			"code":    "IP_DELETE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "IP entry deleted successfully",
	})
}

// SyncIPsToRedis handles PUT /api/v1/ip-list/sync
func (h *IPListHandler) SyncIPsToRedis(c *gin.Context) {
	err := h.ipListService.SyncAllIPsToRedis()
	if err != nil {
		logger.Error("Failed to sync IPs to Redis:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to sync IP entries to Redis cache",
			"code":    "IP_SYNC_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "All active IP entries synced to Redis successfully",
	})
}

// BatchImportIPs handles POST /api/v1/ip-list/batch-import
func (h *IPListHandler) BatchImportIPs(c *gin.Context) {
	var req struct {
		Type string   `json:"type" binding:"required"`
		IPs  []string `json:"ips" binding:"required,min=1,max=1000"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Validation failed: " + err.Error(),
			"code":    "VALIDATION_ERROR",
		})
		return
	}

	if req.Type != model.IPListTypes.Blacklist && req.Type != model.IPListTypes.Whitelist {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid type. Must be 'blacklist' or 'whitelist'",
			"code":    "INVALID_IP_TYPE",
		})
		return
	}

	userID, _ := c.Get("user_id")
	addedCount := 0
	failedCount := 0

	for _, ip := range req.IPs {
		addReq := &service.AddIPRequest{
			IP:   ip,
			Type: req.Type,
		}

		_, err := h.ipListService.AddIP(addReq, userID.(uint))
		if err != nil {
			failedCount++
			continue
		}
		addedCount++
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Batch import completed",
		"added_count":  addedCount,
		"failed_count": failedCount,
		"total":        len(req.IPs),
	})
}
