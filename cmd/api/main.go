// Package main is the entry point for the VibeNet API server.
// It initializes database connections and prepares the runtime for future
// HTTP and WebSocket handlers.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
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

	log.Println("vibenet backend baseline ready")

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	<-shutdown

	log.Println("shutting down gracefully")
}
