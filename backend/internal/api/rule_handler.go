package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/service"
)

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleService *service.RuleService
}

// NewRuleHandler creates a new RuleHandler instance
func NewRuleHandler(ruleService *service.RuleService) *RuleHandler {
	return &RuleHandler{ruleService: ruleService}
}

// ListRules handles GET /api/v1/rules
func (h *RuleHandler) ListRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	filters := make(map[string]interface{})

	if ruleType := c.Query("type"); ruleType != "" {
		filters["type"] = ruleType
	}
	if enabled := c.Query("enabled"); enabled != "" {
		filters["enabled"] = enabled == "true"
	}
	if action := c.Query("action"); action != "" {
		filters["action"] = action
	}
	if search := c.Query("search"); search != "" {
		filters["search"] = search
	}

	response, err := h.ruleService.ListRules(page, pageSize, filters)
	if err != nil {
		logger.Error("Failed to list rules:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve rules",
			"code":    "RULES_LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// CreateRule handles POST /api/v1/rules
func (h *RuleHandler) CreateRule(c *gin.Context) {
	var req service.CreateRuleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Validation failed: " + err.Error(),
			"code":    "VALIDATION_ERROR",
		})
		return
	}

	userID, _ := c.Get("user_id")
	rule, err := h.ruleService.CreateRule(&req, userID.(uint))
	if err != nil {
		if err == service.ErrInvalidRuleType {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Bad Request",
				"message": "Invalid rule type. Valid types: sql_injection, xss, cc_attack, path_traversal, command_injection, ssi_injection, xxe_injection, custom_regex",
				"code":    "INVALID_RULE_TYPE",
			})
			return
		}

		logger.Error("Failed to create rule:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to create rule",
			"code":    "RULE_CREATE_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Rule created successfully",
		"data":    rule,
	})
}

// GetRule handles GET /api/v1/rules/:id
func (h *RuleHandler) GetRule(c *gin.Context) {
	ruleID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid rule ID",
			"code":    "INVALID_RULE_ID",
		})
		return
	}

	rule, err := h.ruleService.GetRuleByID(uint(ruleID))
	if err != nil {
		if err == service.ErrRuleNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Not Found",
				"message": "Rule not found",
				"code":    "RULE_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to retrieve rule",
			"code":    "RULE_GET_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": rule})
}

// UpdateRule handles PUT /api/v1/rules/:id
func (h *RuleHandler) UpdateRule(c *gin.Context) {
	ruleID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid rule ID",
			"code":    "INVALID_RULE_ID",
		})
		return
	}

	var req service.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Validation failed: " + err.Error(),
			"code":    "VALIDATION_ERROR",
		})
		return
	}

	userID, _ := c.Get("user_id")
	rule, err := h.ruleService.UpdateRule(uint(ruleID), &req, userID.(uint))
	if err != nil {
		if err == service.ErrRuleNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Not Found",
				"message": "Rule not found",
				"code":    "RULE_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to update rule",
			"code":    "RULE_UPDATE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule updated successfully",
		"data":    rule,
	})
}

// DeleteRule handles DELETE /api/v1/rules/:id
func (h *RuleHandler) DeleteRule(c *gin.Context) {
	ruleID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid rule ID",
			"code":    "INVALID_RULE_ID",
		})
		return
	}

	err = h.ruleService.DeleteRule(uint(ruleID), 0) // TODO: get user ID from context
	if err != nil {
		if err == service.ErrRuleNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Not Found",
				"message": "Rule not found",
				"code":    "RULE_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to delete rule",
			"code":    "RULE_DELETE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule deleted successfully",
	})
}

// SyncRulesToRedis handles PUT /api/v1/rules/sync
func (h *RuleHandler) SyncRulesToRedis(c *gin.Context) {
	err := h.ruleService.SyncAllRulesToRedis()
	if err != nil {
		logger.Error("Failed to sync rules to Redis:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to sync rules to Redis cache",
			"code":    "RULE_SYNC_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "All active rules synced to Redis successfully",
	})
}
