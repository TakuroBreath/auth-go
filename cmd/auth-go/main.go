package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/TakuroBreath/auth-go/internal/api/handlers"
	"github.com/TakuroBreath/auth-go/internal/api/routes"
	"github.com/TakuroBreath/auth-go/internal/service"
	"github.com/TakuroBreath/auth-go/internal/storage/postgresql"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type mockEmailService struct{}

func (m *mockEmailService) SendIPChangeWarning(userID uuid.UUID, oldIP, newIP string) error {
	log.Printf("Mock email sent to user %s: IP changed from %s to %s", userID, oldIP, newIP)
	return nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	dbConn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	storage, err := postgresql.New(dbConn)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	accessTTL, err := time.ParseDuration(os.Getenv("ACCESS_TOKEN_TTL"))
	if err != nil {
		log.Fatalf("Invalid ACCESS_TOKEN_TTL: %v", err)
	}

	refreshTTL, err := time.ParseDuration(os.Getenv("REFRESH_TOKEN_TTL"))
	if err != nil {
		log.Fatalf("Invalid REFRESH_TOKEN_TTL: %v", err)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	authService := service.New(
		storage,
		[]byte(jwtSecret),
		accessTTL,
		refreshTTL,
		&mockEmailService{},
	)

	authHandler := handlers.NewAuthHandler(authService)

	r := gin.Default()

	routes.SetupRoutes(r, authHandler)

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "8080"
	}

	log.Printf("Starting server on port %s", serverPort)
	if err := r.Run(":" + serverPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
