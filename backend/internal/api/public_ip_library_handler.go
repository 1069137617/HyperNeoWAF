package api

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/service"
)

type PublicIPLibraryHandler struct {
	publicIPLibraryService *service.PublicIPLibraryService
}

func NewPublicIPLibraryHandler(publicIPLibraryService *service.PublicIPLibraryService) *PublicIPLibraryHandler {
	return &PublicIPLibraryHandler{
		publicIPLibraryService: publicIPLibraryService,
	}
}

type SetEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (h *PublicIPLibraryHandler) SetEnabled(c *gin.Context) {
	var req SetEnabledRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Validation failed: " + err.Error(),
			"code":    "VALIDATION_ERROR",
		})
		return
	}

	h.publicIPLibraryService.SetEnabled(req.Enabled)

	c.JSON(http.StatusOK, gin.H{
		"message": "Public IP library enabled status updated",
		"enabled": req.Enabled,
	})
}

func (h *PublicIPLibraryHandler) GetStatus(c *gin.Context) {
	config := h.publicIPLibraryService.GetConfig()

	c.JSON(http.StatusOK, gin.H{
		"enabled":          config.Enabled,
		"last_update_time": config.LastUpdateTime,
		"ip_count":         config.IPCount,
		"update_error":     config.UpdateError,
		"attribution":      service.PublicIPLibraryAttribution,
	})
}

func (h *PublicIPLibraryHandler) TriggerUpdate(c *gin.Context) {
	if !h.publicIPLibraryService.IsEnabled() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Public IP library is not enabled",
			"code":    "NOT_ENABLED",
		})
		return
	}

	go func() {
		if err := h.publicIPLibraryService.Update(); err != nil {
			log.Printf("[PublicIPLibrary] Manual update failed: %v", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"message": "Update triggered successfully",
	})
}
