package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"log"

	"github.com/TakuroBreath/auth-go/internal/storage/postgresql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
	ErrTokenUsed    = errors.New("refresh token already used")
	ErrIPMismatch   = errors.New("IP address mismatch")
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type Claims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid"`
	IP     string `json:"ip"`
}

type Service struct {
	storage      *postgresql.Storage
	jwtKey       []byte
	accessTTL    time.Duration
	refreshTTL   time.Duration
	emailService EmailService
}

type EmailService interface {
	SendIPChangeWarning(userID uuid.UUID, oldIP, newIP string) error
}

func New(storage *postgresql.Storage, jwtKey []byte, accessTTL, refreshTTL time.Duration, emailService EmailService) *Service {
	return &Service{
		storage:      storage,
		jwtKey:       jwtKey,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
		emailService: emailService,
	}
}

func (s *Service) CreateTokenPair(ctx context.Context, userID uuid.UUID, ip string) (*TokenPair, error) {
	accessToken, err := s.createAccessToken(userID, ip)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.createRefreshToken(ctx, userID, ip)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) createAccessToken(userID uuid.UUID, ip string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID: userID.String(),
		IP:     ip,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(s.jwtKey)
}

func (s *Service) createRefreshToken(ctx context.Context, userID uuid.UUID, ip string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	refreshStr := base64.URLEncoding.EncodeToString(tokenBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshStr), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	token := postgresql.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: string(hash),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.refreshTTL),
		IssuedIP:  ip,
	}

	if err := s.storage.SaveRefreshToken(ctx, token); err != nil {
		return "", err
	}

	tokenData := token.ID.String() + ":" + refreshStr
	return base64.URLEncoding.EncodeToString([]byte(tokenData)), nil
}

func (s *Service) RefreshTokens(ctx context.Context, refreshToken string, ip string) (*TokenPair, error) {
	tokenData, err := base64.URLEncoding.DecodeString(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	parts := strings.Split(string(tokenData), ":")
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}

	tokenID, err := uuid.Parse(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	storedToken, err := s.storage.GetRefreshToken(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	if storedToken.IsUsed {
		return nil, ErrTokenUsed
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedToken.TokenHash), []byte(parts[1])); err != nil {
		return nil, ErrInvalidToken
	}

	if ip != storedToken.IssuedIP {
		if err := s.emailService.SendIPChangeWarning(storedToken.UserID, storedToken.IssuedIP, ip); err != nil {
			log.Printf("Failed to send IP change warning: %v", err)
		}
	}

	if err := s.storage.MarkTokenAsUsed(ctx, tokenID); err != nil {
		return nil, err
	}

	return s.CreateTokenPair(ctx, storedToken.UserID, ip)
}
