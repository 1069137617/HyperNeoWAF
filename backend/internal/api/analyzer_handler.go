package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/waf-project/backend/internal/pkg/analyzer"
)

type AnalyzerHandler struct {
	dispatcher *analyzer.Dispatcher
}

func NewAnalyzerHandler(dispatcher *analyzer.Dispatcher) *AnalyzerHandler {
	return &AnalyzerHandler{
		dispatcher: dispatcher,
	}
}

func (h *AnalyzerHandler) RegisterRoutes(r *gin.RouterGroup) {
	analyzers := r.Group("/analyzers")
	{
		analyzers.GET("", h.ListAnalyzers)
		analyzers.GET("/:name", h.GetAnalyzer)
		analyzers.PUT("/:name/enable", h.EnableAnalyzer)
		analyzers.PUT("/:name/disable", h.DisableAnalyzer)
		analyzers.PUT("/:name/threshold", h.SetAnalyzerThreshold)
		analyzers.POST("/:name/reset", h.ResetAnalyzer)
	}

	rateLimit := r.Group("/rate-limit")
	{
		rateLimit.GET("", h.GetRateLimitConfig)
		rateLimit.PUT("", h.SetRateLimitConfig)
		rateLimit.PUT("/enable", h.EnableRateLimit)
		rateLimit.PUT("/disable", h.DisableRateLimit)
		rateLimit.POST("/reset", h.ResetRateLimit)
	}

	analyzers.POST("/batch/enable", h.BatchEnable)
	analyzers.POST("/batch/disable", h.BatchDisable)
	analyzers.POST("/reset-all", h.ResetAll)
	analyzers.GET("/settings/export", h.ExportSettings)
	analyzers.POST("/settings/import", h.ImportSettings)
}

type AnalyzerStatusResponse struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Enabled     bool    `json:"enabled"`
	Threshold   float64 `json:"threshold"`
	Description string  `json:"description"`
}

type ListAnalyzersResponse struct {
	Analyzers []AnalyzerStatusResponse `json:"analyzers"`
	Total     int                      `json:"total"`
}

func (h *AnalyzerHandler) ListAnalyzers(c *gin.Context) {
	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	analyzerSettings := settings.GetAllAnalyzerSettings()
	analyzers := make([]AnalyzerStatusResponse, 0, len(analyzerSettings))

	for _, a := range analyzerSettings {
		analyzers = append(analyzers, AnalyzerStatusResponse{
			Name:        a.Name,
			Type:        a.Type,
			Enabled:     a.Enabled,
			Threshold:   a.Threshold,
			Description: a.Description,
		})
	}

	c.JSON(http.StatusOK, ListAnalyzersResponse{
		Analyzers: analyzers,
		Total:     len(analyzers),
	})
}

func (h *AnalyzerHandler) GetAnalyzer(c *gin.Context) {
	name := c.Param("name")

	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	analyzerSetting, err := settings.GetAnalyzerSetting(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "analyzer not found: " + name,
		})
		return
	}

	c.JSON(http.StatusOK, AnalyzerStatusResponse{
		Name:        analyzerSetting.Name,
		Type:        analyzerSetting.Type,
		Enabled:     analyzerSetting.Enabled,
		Threshold:   analyzerSetting.Threshold,
		Description: analyzerSetting.Description,
	})
}

type EnableRequest struct {
	Enabled bool `json:"enabled"`
}

func (h *AnalyzerHandler) EnableAnalyzer(c *gin.Context) {
	name := c.Param("name")

	var req EnableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if err := h.dispatcher.SetAnalyzerEnabled(name, true); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "analyzer enabled",
		"name":    name,
		"enabled": true,
	})
}

func (h *AnalyzerHandler) DisableAnalyzer(c *gin.Context) {
	name := c.Param("name")

	if err := h.dispatcher.SetAnalyzerEnabled(name, false); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "analyzer disabled",
		"name":    name,
		"enabled": false,
	})
}

type SetThresholdRequest struct {
	Threshold float64 `json:"threshold" binding:"required,min=0,max=1"`
}

func (h *AnalyzerHandler) SetAnalyzerThreshold(c *gin.Context) {
	name := c.Param("name")

	var req SetThresholdRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "threshold must be between 0 and 1",
		})
		return
	}

	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	if err := settings.SetAnalyzerThreshold(name, req.Threshold); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "threshold updated",
		"name":      name,
		"threshold": req.Threshold,
	})
}

func (h *AnalyzerHandler) ResetAnalyzer(c *gin.Context) {
	name := c.Param("name")

	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	if err := settings.SetAnalyzerEnabled(name, true); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	if err := settings.SetAnalyzerThreshold(name, 0.7); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "analyzer reset to defaults",
		"name":      name,
		"enabled":   true,
		"threshold": 0.7,
	})
}

type RateLimitConfigResponse struct {
	Enabled           bool `json:"enabled"`
	IPLimit           int  `json:"ip_limit"`
	IPWindowSecs      int  `json:"ip_window_secs"`
	URLLimit          int  `json:"url_limit"`
	URLWindowSecs     int  `json:"url_window_secs"`
	UALimit           int  `json:"ua_limit"`
	UAWindowSecs      int  `json:"ua_window_secs"`
	BlockDurationSecs int  `json:"block_duration_secs"`
}

func (h *AnalyzerHandler) GetRateLimitConfig(c *gin.Context) {
	config := h.dispatcher.GetRateLimitConfig()

	c.JSON(http.StatusOK, RateLimitConfigResponse{
		Enabled:           config.Enabled,
		IPLimit:           config.IPLimit,
		IPWindowSecs:      config.IPWindowSecs,
		URLLimit:          config.URLLimit,
		URLWindowSecs:     config.URLWindowSecs,
		UALimit:           config.UALimit,
		UAWindowSecs:      config.UAWindowSecs,
		BlockDurationSecs: config.BlockDurationSecs,
	})
}

type SetRateLimitConfigRequest struct {
	IPLimit           int `json:"ip_limit" binding:"required,min=1"`
	IPWindowSecs      int `json:"ip_window_secs" binding:"required,min=1"`
	URLLimit          int `json:"url_limit" binding:"required,min=1"`
	URLWindowSecs     int `json:"url_window_secs" binding:"required,min=1"`
	UALimit           int `json:"ua_limit" binding:"required,min=1"`
	UAWindowSecs      int `json:"ua_window_secs" binding:"required,min=1"`
	BlockDurationSecs int `json:"block_duration_secs" binding:"required,min=1"`
}

func (h *AnalyzerHandler) SetRateLimitConfig(c *gin.Context) {
	var req SetRateLimitConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	config := &analyzer.RateLimitConfig{
		Enabled:           true,
		IPLimit:           req.IPLimit,
		IPWindowSecs:      req.IPWindowSecs,
		URLLimit:          req.URLLimit,
		URLWindowSecs:     req.URLWindowSecs,
		UALimit:           req.UALimit,
		UAWindowSecs:      req.UAWindowSecs,
		BlockDurationSecs: req.BlockDurationSecs,
	}

	if err := h.dispatcher.SetRateLimitConfig(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "rate limit config updated",
		"config":  config,
	})
}

func (h *AnalyzerHandler) EnableRateLimit(c *gin.Context) {
	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	if err := settings.SetRateLimitEnabled(true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "rate limit enabled",
		"enabled": true,
	})
}

func (h *AnalyzerHandler) DisableRateLimit(c *gin.Context) {
	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	if err := settings.SetRateLimitEnabled(false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "rate limit disabled",
		"enabled": false,
	})
}

func (h *AnalyzerHandler) ResetRateLimit(c *gin.Context) {
	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	config := &analyzer.RateLimitConfig{
		Enabled:           true,
		IPLimit:           60,
		IPWindowSecs:      60,
		URLLimit:          120,
		URLWindowSecs:     60,
		UALimit:           200,
		UAWindowSecs:      60,
		BlockDurationSecs: 300,
	}

	if err := settings.SetRateLimitConfig(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "rate limit reset to defaults",
		"config":  config,
	})
}

type BatchNamesRequest struct {
	Names []string `json:"names" binding:"required"`
}

func (h *AnalyzerHandler) BatchEnable(c *gin.Context) {
	var req BatchNamesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "names are required",
		})
		return
	}

	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	enabled := make([]string, 0)
	failed := make([]string, 0)

	for _, name := range req.Names {
		if err := settings.SetAnalyzerEnabled(name, true); err != nil {
			failed = append(failed, name)
		} else {
			enabled = append(enabled, name)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "batch enable completed",
		"enabled": enabled,
		"failed":  failed,
	})
}

func (h *AnalyzerHandler) BatchDisable(c *gin.Context) {
	var req BatchNamesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "names are required",
		})
		return
	}

	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	disabled := make([]string, 0)
	failed := make([]string, 0)

	for _, name := range req.Names {
		if err := settings.SetAnalyzerEnabled(name, false); err != nil {
			failed = append(failed, name)
		} else {
			disabled = append(disabled, name)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "batch disable completed",
		"disabled": disabled,
		"failed":   failed,
	})
}

func (h *AnalyzerHandler) ResetAll(c *gin.Context) {
	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	if err := settings.ResetToDefaults(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "all settings reset to defaults",
		"reset_at": time.Now(),
	})
}

func (h *AnalyzerHandler) ExportSettings(c *gin.Context) {
	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	jsonStr, err := settings.ToJSON()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"settings":    jsonStr,
		"exported_at": time.Now(),
	})
}

type ImportSettingsRequest struct {
	Settings string `json:"settings" binding:"required"`
}

func (h *AnalyzerHandler) ImportSettings(c *gin.Context) {
	var req ImportSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "settings JSON is required",
		})
		return
	}

	settings := h.dispatcher.GetSettings()
	if settings == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "settings not initialized",
		})
		return
	}

	if err := settings.FromJSON(strings.TrimSpace(req.Settings)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid settings JSON: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "settings imported successfully",
		"imported_at": time.Now(),
	})
}
