package api

// Copyright 2026 Yinuo. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/service"
)

type CaptchaHandler struct {
	captchaService *service.CaptchaService
}

func NewCaptchaHandler(captchaService *service.CaptchaService) *CaptchaHandler {
	return &CaptchaHandler{
		captchaService: captchaService,
	}
}

func (h *CaptchaHandler) Generate(c *gin.Context) {
	clientIP := c.ClientIP()
	redirectURL := c.Query("redirect")
	if redirectURL == "" {
		redirectURL = "/"
	}

	if h.captchaService.IsVerified(clientIP) {
		token, _ := h.captchaService.GetVerificationToken(clientIP)
		c.JSON(http.StatusOK, gin.H{
			"verified":    true,
			"token":       token,
			"valid_until": "24 hours",
		})
		return
	}

	token, verifyToken := h.captchaService.GenerateCaptcha(clientIP, redirectURL)

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"verify_url": "/captcha?token=" + token + "&redirect=" + redirectURL,
	})
}

func (h *CaptchaHandler) Verify(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "token is required",
			"code":    "INVALID_REQUEST",
		})
		return
	}

	clientIP := c.ClientIP()
	redirectURL, verifyToken, err := h.captchaService.VerifyCaptcha(req.Token, clientIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Verification Failed",
			"message": err.Error(),
			"code":    "CAPTCHA_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"redirect_url":    redirectURL,
		"verify_token":    verifyToken,
		"valid_for_hours": 24,
	})
}

func (h *CaptchaHandler) Check(c *gin.Context) {
	clientIP := c.ClientIP()

	if h.captchaService.IsVerified(clientIP) {
		token, _ := h.captchaService.GetVerificationToken(clientIP)
		c.JSON(http.StatusOK, gin.H{
			"verified": true,
			"token":    token,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"verified": false,
	})
}
