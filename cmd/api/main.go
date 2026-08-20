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
	"github.com/ChamathDilshanC/VibeNet-backend/internal/storage"
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

	postgresRepo := db.NewPostgresRepo(postgresDB)
	// Messages share the same Postgres connection as the rest of VibeNet's
	// relational data — no separate connection/credentials needed (this used
	// to be a DynamoDB table; see internal/db/messages.go).
	messageRepo := db.NewMessageRepo(postgresDB)
	jwtManager := auth.NewJWTManager()
	googleCfg := auth.LoadGoogleOAuthConfig()

	// S3-compatible storage (encrypted file/image attachments, via Supabase
	// Storage) is optional: a deployment without SUPABASE_S3_* configured
	// still boots, just with the upload endpoints answering 503 rather than
	// the whole server failing to start.
	s3Presign, err := storage.NewPresignClient(ctx, storage.LoadS3Config())
	if err != nil {
		log.Printf("s3 attachments disabled: %v", err)
		s3Presign = nil
	}

	// Avatar uploads (profile/group photos) go to Supabase Storage's
	// S3-compatible API. Optional like s3Presign: a deployment without
	// SUPABASE_S3_* configured still boots, just with upload endpoints
	// answering 503.
	avatarStore, err := storage.NewAvatarStore(ctx, storage.LoadAvatarStoreConfig())
	if err != nil {
		log.Printf("avatar uploads disabled: %v", err)
		avatarStore = nil
	}

	apiHandler := api.NewHandler(postgresRepo, messageRepo, jwtManager, googleCfg, s3Presign, avatarStore)
	wsHub := websocket.NewHub(postgresRepo)
	// Let the REST layer push live profile updates (user_update) to connected
	// clients. Wired after construction to avoid an api⇄websocket import cycle.
	apiHandler.SetBroadcaster(wsHub)
	wsHandler := websocket.NewHandler(wsHub, apiHandler, messageRepo)

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
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
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

		// Messages live on this same postgres connection now, so there's no
		// separate "dynamodb" entry to check anymore.
		services := map[string]serviceHealth{
			"postgres": check(func() error { return db.PingPostgres(healthCtx, postgresDB) }),
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

	// Render (and most PaaS hosts) assign the listen port via $PORT and route
	// traffic to whatever it resolves to, ignoring app-specific env vars — so
	// PORT must win when set, with APP_PORT as the local-dev fallback.
	port := utils.GetEnv("PORT", utils.GetEnv("APP_PORT", "8080"))
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
