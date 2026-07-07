// Package main is the entry point for the VibeNet API server.
// It wires database connections, REST routes, and the WebSocket hub.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
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

	apiHandler := api.NewHandler(postgresRepo, jwtManager, googleCfg)
	wsHub := websocket.NewHub()
	wsHandler := websocket.NewHandler(wsHub, apiHandler, dynamoRepo)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{utils.GetEnv("CORS_ALLOWED_ORIGINS", "*")},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	router.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
