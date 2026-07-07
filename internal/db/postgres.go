// Package db provides database connection and lifecycle management for VibeNet.
// It implements the dual-database strategy: PostgreSQL for relational metadata
// and Amazon DynamoDB for high-volume encrypted message storage.
package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/google/uuid"
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

// PostgresRepo wraps a GORM database handle with user-centric persistence methods.
type PostgresRepo struct {
	db *gorm.DB
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

	database, err := gorm.Open(postgres.Open(cfg.DSN()), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	sqlDB, err := database.DB()
	if err != nil {
		return nil, fmt.Errorf("retrieve underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if err := database.AutoMigrate(&models.User{}, &models.Contact{}); err != nil {
		return nil, fmt.Errorf("auto-migrate postgres schema: %w", err)
	}

	return database, nil
}

// NewPostgresRepo returns a repository backed by the provided GORM handle.
func NewPostgresRepo(database *gorm.DB) *PostgresRepo {
	return &PostgresRepo{db: database}
}

// CreateUser inserts a new standard-registration user with a bcrypt password hash and E2EE public key.
func (r *PostgresRepo) CreateUser(ctx context.Context, username, passwordHash, publicKey string, email *string) (*models.User, error) {
	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: &passwordHash,
		PublicKey:    &publicKey,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

// CreateOrGetUserByGoogle finds an existing Google OAuth user or creates a new account
// without a password or public key. The client must upload its E2EE public key later.
func (r *PostgresRepo) CreateOrGetUserByGoogle(ctx context.Context, googleID, email, username string) (*models.User, error) {
	var existing models.User
	err := r.db.WithContext(ctx).Where("google_id = ?", googleID).First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("lookup google user: %w", err)
	}

	emailCopy := email
	googleIDCopy := googleID
	user := &models.User{
		Username: username,
		Email:    &emailCopy,
		GoogleID: &googleIDCopy,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("create google user: %w", err)
	}
	return user, nil
}

// UpdatePublicKey persists a user's E2EE public key after OAuth login or key rotation.
func (r *PostgresRepo) UpdatePublicKey(ctx context.Context, userID uuid.UUID, publicKey string) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Update("public_key", publicKey)
	if result.Error != nil {
		return fmt.Errorf("update public key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// GetUserByUsername retrieves a user record by unique username for credential verification.
func (r *PostgresRepo) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByID retrieves a user record by primary key.
func (r *PostgresRepo) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetPublicKey returns the E2EE public key for a user, used by peers before encrypting messages.
func (r *PostgresRepo) GetPublicKey(ctx context.Context, userID uuid.UUID) (string, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Select("public_key").
		Where("user_id = ?", userID).
		First(&user).Error; err != nil {
		return "", err
	}
	if user.PublicKey == nil || *user.PublicKey == "" {
		return "", gorm.ErrRecordNotFound
	}
	return *user.PublicKey, nil
}

// PingPostgres verifies that the PostgreSQL connection is alive.
func PingPostgres(ctx context.Context, database *gorm.DB) error {
	sqlDB, err := database.DB()
	if err != nil {
		return fmt.Errorf("retrieve underlying sql.DB: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

// ClosePostgres gracefully closes the PostgreSQL connection pool.
func ClosePostgres(database *gorm.DB) {
	sqlDB, err := database.DB()
	if err != nil {
		log.Printf("postgres close: failed to retrieve sql.DB: %v", err)
		return
	}
	if err := sqlDB.Close(); err != nil {
		log.Printf("postgres close: %v", err)
	}
}
