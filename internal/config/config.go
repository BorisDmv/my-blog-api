package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port               string
	DatabaseURL        string
	AuthToken          string
	CorsAllowedOrigins []string
}

func Load() Config {
	_ = godotenv.Load()

	cfg := Config{
		Port:               getEnv("PORT", "8080"),
		DatabaseURL:        getEnv("DATABASE_URL", ""),
		AuthToken:          getEnv("AUTH_TOKEN", ""),
		CorsAllowedOrigins: splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "*")),
	}

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if cfg.AuthToken == "" {
		log.Fatal("AUTH_TOKEN is required")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}
