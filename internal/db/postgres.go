// Package db provides database connection and lifecycle management for VibeNet.
// It implements the dual-database strategy: PostgreSQL for relational metadata
// and Amazon DynamoDB for high-volume encrypted message storage.
package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// PostgresConfig holds the connection parameters for the AWS RDS PostgreSQL instance.
type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// LoadPostgresConfig builds a PostgresConfig from environment variables.
func LoadPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Host:     utils.GetEnv("POSTGRES_HOST", "localhost"),
		Port:     utils.GetEnv("POSTGRES_PORT", "5432"),
		User:     utils.GetEnv("POSTGRES_USER", "vibenet"),
		Password: utils.GetEnv("POSTGRES_PASSWORD", ""),
		DBName:   utils.GetEnv("POSTGRES_DB", "vibenet"),
		SSLMode:  utils.GetEnv("POSTGRES_SSLMODE", "require"),
	}
}

// DSN returns a PostgreSQL connection string suitable for the GORM postgres driver.
func (c PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

// ConnectPostgres establishes a connection to PostgreSQL and runs initial schema migrations
// for the Users and Contacts models defined in the architecture.
func ConnectPostgres(cfg PostgresConfig) (*gorm.DB, error) {
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN()), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("retrieve underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if err := db.AutoMigrate(&models.User{}, &models.Contact{}); err != nil {
		return nil, fmt.Errorf("auto-migrate postgres schema: %w", err)
	}

	return db, nil
}

// PingPostgres verifies that the PostgreSQL connection is alive.
func PingPostgres(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("retrieve underlying sql.DB: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

// ClosePostgres gracefully closes the PostgreSQL connection pool.
func ClosePostgres(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("postgres close: failed to retrieve sql.DB: %v", err)
		return
	}
	if err := sqlDB.Close(); err != nil {
		log.Printf("postgres close: %v", err)
	}
}
