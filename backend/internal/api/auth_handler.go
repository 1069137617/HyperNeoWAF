package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/middleware"
	"github.com/waf-project/backend/internal/service"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService *service.AuthService
	jwtAuth     *middleware.JWTAuth
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(authService *service.AuthService, jwtAuth *middleware.JWTAuth) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtAuth:     jwtAuth,
	}
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body: " + err.Error(),
			"code":    "INVALID_REQUEST_BODY",
		})
		return
	}

	loginResp, err := h.authService.Authenticate(&req)
	if err != nil {
		statusCode := http.StatusUnauthorized
		message := "Invalid credentials"

		if err == service.ErrUserNotFound || err == service.ErrInvalidCredentials {
			statusCode = http.StatusUnauthorized
		} else {
			statusCode = http.StatusInternalServerError
			message = "Authentication failed"
		}

		c.JSON(statusCode, gin.H{
			"error":   "Authentication Failed",
			"message": message,
			"code":    "AUTH_FAILED",
		})
		return
	}

	// Generate JWT tokens
	accessToken, refreshToken, tokenErr := h.jwtAuth.GenerateTokenPair(
		loginResp.User.ID,
		loginResp.User.Username,
		loginResp.User.Role,
	)

	if tokenErr != nil {
		logger.Error("Failed to generate tokens:", tokenErr)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to generate authentication tokens",
			"code":    "TOKEN_GENERATION_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Login successful",
		"user":          loginResp.User,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    loginResp.ExpiresIn,
		"token_type":    "Bearer",
	})
}

// RefreshToken handles POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "refresh_token is required",
			"code":    "MISSING_REFRESH_TOKEN",
		})
		return
	}

	// Validate refresh token
	claims, err := h.jwtAuth.ValidateToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Unauthorized",
			"message": "Invalid or expired refresh token",
			"code":    "INVALID_REFRESH_TOKEN",
		})
		return
	}

	// Generate new token pair
	newAccessToken, newRefreshToken, tokenErr := h.jwtAuth.GenerateTokenPair(
		claims.UserID,
		claims.Username,
		claims.Role,
	)

	if tokenErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to generate new tokens",
			"code":    "TOKEN_GENERATION_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Token refreshed successfully",
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"expires_in":    86400,
		"token_type":    "Bearer",
	})
}

// GetProfile handles GET /api/v1/auth/profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	id := userID.(uint)

	user, err := h.authService.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "User not found",
			"code":    "USER_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

// ChangePassword handles PUT /api/v1/auth/password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")
	id := userID.(uint)

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8,max=128"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request: " + err.Error(),
			"code":    "INVALID_REQUEST",
		})
		return
	}

	err := h.authService.ChangePassword(id, req.OldPassword, req.NewPassword)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Current password is incorrect",
				"code":    "INVALID_CURRENT_PASSWORD",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to change password",
			"code":    "PASSWORD_CHANGE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}
