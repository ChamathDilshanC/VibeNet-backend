// Package main is the entry point for the VibeNet API server.
// It wires database connections, REST routes, and the WebSocket hub.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/api"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/auth"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/websocket"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, using system environment variables")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	postgresCfg := db.LoadPostgresConfig()
	postgresDB, err := db.ConnectPostgres(postgresCfg)
	if err != nil {
		log.Fatalf("postgres initialization failed: %v", err)
	}
	defer db.ClosePostgres(postgresDB)

	if err := db.PingPostgres(ctx, postgresDB); err != nil {
		log.Fatalf("postgres health check failed: %v", err)
	}
	log.Println("postgresql connection established")

	dynamoCfg := db.LoadDynamoDBConfig()
	dynamoClient, err := db.ConnectDynamoDB(ctx, dynamoCfg)
	if err != nil {
		log.Fatalf("dynamodb initialization failed: %v", err)
	}
	defer db.CloseDynamoDB(dynamoClient)

	if err := db.PingDynamoDB(ctx, dynamoClient, db.MessagesTableName(dynamoCfg)); err != nil {
		log.Printf("dynamodb health check warning: %v", err)
	} else {
		log.Println("dynamodb connection established")
	}

	postgresRepo := db.NewPostgresRepo(postgresDB)
	dynamoRepo := db.NewDynamoRepo(dynamoClient, db.MessagesTableName(dynamoCfg))
	jwtManager := auth.NewJWTManager()
	googleCfg := auth.LoadGoogleOAuthConfig()

	apiHandler := api.NewHandler(postgresRepo, dynamoRepo, jwtManager, googleCfg)
	wsHub := websocket.NewHub()
	wsHandler := websocket.NewHandler(wsHub, apiHandler, dynamoRepo)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	// CORS_ALLOWED_ORIGINS is a comma-separated list; split it into individual
	// origins so multiple front-ends (e.g. dev + production) are matched correctly.
	allowedOrigins := make([]string, 0)
	for _, origin := range strings.Split(utils.GetEnv("CORS_ALLOWED_ORIGINS", "*"), ",") {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			allowedOrigins = append(allowedOrigins, trimmed)
		}
	}
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"*"}
	}

	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	startTime := time.Now()
	appVersion := utils.GetEnv("APP_VERSION", "1.0.0")

	// Root landing / API documentation page, plus a clean JSON 404 for unknown routes.
	router.Get("/", api.LandingHandler(appVersion, utils.GetEnv("APP_ENV", "development")))
	router.NotFound(api.NotFoundHandler())

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		healthCtx, healthCancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer healthCancel()

		type serviceHealth struct {
			Status    string `json:"status"`
			LatencyMS int64  `json:"latency_ms"`
			Error     string `json:"error,omitempty"`
		}

		// check runs a single dependency ping and records its round-trip latency.
		check := func(ping func() error) serviceHealth {
			start := time.Now()
			err := ping()
			result := serviceHealth{LatencyMS: time.Since(start).Milliseconds()}
			if err != nil {
				result.Status = "down"
				result.Error = err.Error()
			} else {
				result.Status = "up"
			}
			return result
		}

		services := map[string]serviceHealth{
			"postgres": check(func() error { return db.PingPostgres(healthCtx, postgresDB) }),
			"dynamodb": check(func() error {
				return db.PingDynamoDB(healthCtx, dynamoClient, db.MessagesTableName(dynamoCfg))
			}),
		}

		healthy := true
		for _, s := range services {
			if s.Status != "up" {
				healthy = false
			}
		}

		response := struct {
			Status        string                   `json:"status"`
			Service       string                   `json:"service"`
			Version       string                   `json:"version"`
			Environment   string                   `json:"environment"`
			Timestamp     string                   `json:"timestamp"`
			UptimeSeconds int64                    `json:"uptime_seconds"`
			Services      map[string]serviceHealth `json:"services"`
		}{
			Service:       "vibenet-backend",
			Version:       appVersion,
			Environment:   utils.GetEnv("APP_ENV", "development"),
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			UptimeSeconds: int64(time.Since(startTime).Seconds()),
			Services:      services,
		}
		if healthy {
			response.Status = "ok"
		} else {
			response.Status = "degraded"
		}

		w.Header().Set("Content-Type", "application/json")
		if healthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ") // pretty-print by default
		_ = encoder.Encode(response)
	})

	apiHandler.RegisterRoutes(router)
	router.Get("/ws", wsHandler.ServeHTTP)

	port := utils.GetEnv("APP_PORT", "8080")
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("vibenet backend listening on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	<-shutdown

	log.Println("shutting down gracefully")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}
