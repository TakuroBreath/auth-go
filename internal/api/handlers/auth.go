package handlers

import (
	"log"

	"github.com/TakuroBreath/auth-go/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	authService *service.Service
}

func NewAuthHandler(authService *service.Service) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

func (h *AuthHandler) CreateTokens(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid user ID"})
		return
	}

	clientIP := c.GetString("client_ip")
	tokens, err := h.authService.CreateTokenPair(c.Request.Context(), userID, clientIP)
	if err != nil {
		log.Printf("Error creating tokens: %v", err)
		c.JSON(500, gin.H{"error": "failed to create tokens"})
		return
	}

	c.JSON(200, tokens)
}

func (h *AuthHandler) RefreshTokens(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	clientIP := c.GetString("client_ip")
	tokens, err := h.authService.RefreshTokens(c.Request.Context(), req.RefreshToken, clientIP)
	if err != nil {
		log.Printf("Error refreshing tokens: %v", err)
		c.JSON(401, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	c.JSON(200, tokens)
}
