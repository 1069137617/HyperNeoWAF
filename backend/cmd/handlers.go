package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// authMiddleware - JWT 认证中间件
// 验证请求头中的 Authorization Bearer Token
// 将用户信息设置到 gin.Context 中供后续处理器使用
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取 Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// 期望格式: Bearer <token>
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// TODO: 实现实际的 JWT 验证逻辑
		// 目前接受任何长度 >= 10 的非空 token（占位实现）
		if len(tokenString) < 10 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// TODO: 从 token 中提取用户信息并设置到 context
		c.Set("user_id", "placeholder-user-id")
		c.Next()
	}
}

// 占位处理器 - Phase 3 中已由 internal/api 实现替代
// 以下处理器仅作为快速开发期间的占位符使用

// handleLogin - 登录处理器（占位）
func handleLogin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Login endpoint - TODO: implement",
	})
}

// handleRefreshToken - 刷新令牌处理器（占位）
func handleRefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Refresh token endpoint - TODO: implement",
	})
}

// handleGetRules - 获取规则列表处理器（占位）
func handleGetRules(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    []interface{}{},
		"message": "Get rules endpoint - TODO: implement",
	})
}

// handleCreateRule - 创建规则处理器（占位）
func handleCreateRule(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"message": "Create rule endpoint - TODO: implement",
	})
}

// handleUpdateRule - 更新规则处理器（占位）
func handleUpdateRule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Update rule endpoint - TODO: implement",
	})
}

// handleDeleteRule - 删除规则处理器（占位）
func handleDeleteRule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Delete rule endpoint - TODO: implement",
	})
}

// handleSyncRulesToRedis - 同步规则到 Redis 处理器（占位）
func handleSyncRulesToRedis(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Sync rules to Redis endpoint - TODO: implement",
	})
}

// handleReceiveLogs - 接收 OpenResty 日志处理器（占位）
func handleReceiveLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Receive logs from OpenResty - TODO: implement",
	})
}

// handleGetLogs - 获取日志列表处理器（占位）
func handleGetLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    []interface{}{},
		"message": "Get logs endpoint - TODO: implement",
	})
}

// handleExportLogs - 导出日志处理器（占位）
func handleExportLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Export logs endpoint - TODO: implement",
	})
}

// handleGetIPList - 获取 IP 列表处理器（占位）
func handleGetIPList(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    []interface{}{},
		"message": "Get IP list endpoint - TODO: implement",
	})
}

// handleAddIPEntry - 添加 IP 条目处理器（占位）
func handleAddIPEntry(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"message": "Add IP entry endpoint - TODO: implement",
	})
}

// handleDeleteIPEntry - 删除 IP 条目处理器（占位）
func handleDeleteIPEntry(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Delete IP entry endpoint - TODO: implement",
	})
}

// handleDashboardStats - 仪表盘统计处理器（占位）
func handleDashboardStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    gin.H{},
		"message": "Dashboard stats endpoint - TODO: implement",
	})
}

// handleDashboardTrends - 仪表盘趋势处理器（占位）
func handleDashboardTrends(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    []interface{}{},
		"message": "Dashboard trends endpoint - TODO: implement",
	})
}

// handleRecentEvents - 最近事件处理器（占位）
func handleRecentEvents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    []interface{}{},
		"message": "Recent events endpoint - TODO: implement",
	})
}

// handleTopAttacks - Top 攻击处理器（占位）
func handleTopAttacks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":    []interface{}{},
		"message": "Top attacks endpoint - TODO: implement",
	})
}
