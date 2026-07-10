// Package db provides database connection and lifecycle management for VibeNet.
// It implements the dual-database strategy: PostgreSQL for relational metadata
// and Amazon DynamoDB for high-volume encrypted message storage.
package db

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// chatPINTTL defines how long a freshly generated chat-initiation PIN stays valid.
const chatPINTTL = 5 * time.Minute

// ErrChatPINRequired is returned when a target user mandates a chat PIN and the
// supplied PIN is missing, incorrect, or expired. Callers should map this to 403.
var ErrChatPINRequired = errors.New("invalid or expired chat PIN")

// ErrUsernameTaken is returned when a profile update would collide with the
// username of another account. Callers should map this to 409.
var ErrUsernameTaken = errors.New("username already taken")

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
//
// avatarURL is the Google account photo. On an existing account it is re-synced when it
// differs from what we hold, so a photo changed in Google shows up after the next sign-in.
// The username is only used when provisioning: renaming in Google must not silently
// overwrite a username the person later chose in VibeNet's profile settings.
func (r *PostgresRepo) CreateOrGetUserByGoogle(ctx context.Context, googleID, email, username, avatarURL string) (*models.User, error) {
	var existing models.User
	err := r.db.WithContext(ctx).Where("google_id = ?", googleID).First(&existing).Error
	if err == nil {
		if avatarURL != "" && (existing.AvatarURL == nil || *existing.AvatarURL != avatarURL) {
			if err := r.db.WithContext(ctx).Model(&existing).
				Update("avatar_url", avatarURL).Error; err != nil {
				// A stale photo must not block sign-in.
				log.Printf("refresh google avatar for %s: %v", existing.UserID, err)
			} else {
				existing.AvatarURL = &avatarURL
			}
		}
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
	if avatarURL != "" {
		avatarCopy := avatarURL
		user.AvatarURL = &avatarCopy
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("create google user: %w", err)
	}
	return user, nil
}

// UpdateProfile renames the authenticated user and returns the updated record.
// A collision with another account's username yields ErrUsernameTaken.
func (r *PostgresRepo) UpdateProfile(ctx context.Context, userID uuid.UUID, username string) (*models.User, error) {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Update("username", username)
	if result.Error != nil {
		if isUniqueViolation(result.Error) {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("update profile: %w", result.Error)
	}
	// RowsAffected is 0 both when the user is gone and when the username is
	// unchanged, so confirm existence by reading the record back.
	return r.GetUserByID(ctx, userID)
}

// isUniqueViolation reports whether err is a unique-constraint failure. GORM
// surfaces the driver error verbatim and pgx is only an indirect dependency
// here, so match on the message the way the API layer already does.
func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique")
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
//
// When the target user has enabled the anti-spam rotating PIN (RequireChatPIN), the
// caller must supply the current 4-digit providedPIN. The PIN is validated against the
// stored value and its expiry; a missing, incorrect, or expired PIN yields
// ErrChatPINRequired so the API layer can respond with 403 Forbidden.
func (r *PostgresRepo) GetPublicKey(ctx context.Context, userID uuid.UUID, providedPIN string) (string, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Select("public_key", "require_chat_pin", "chat_pin", "chat_pin_expiry").
		Where("user_id = ?", userID).
		First(&user).Error; err != nil {
		return "", err
	}

	if user.RequireChatPIN {
		if providedPIN == "" || providedPIN != user.ChatPIN || !time.Now().Before(user.ChatPINExpiry) {
			return "", ErrChatPINRequired
		}
	}

	if user.PublicKey == nil || *user.PublicKey == "" {
		return "", gorm.ErrRecordNotFound
	}
	return *user.PublicKey, nil
}

// ToggleChatPIN enables or disables the anti-spam chat-initiation PIN requirement for a user.
// Disabling the requirement leaves any previously generated PIN in place but inert.
func (r *PostgresRepo) ToggleChatPIN(ctx context.Context, userID uuid.UUID, require bool) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Update("require_chat_pin", require)
	if result.Error != nil {
		return fmt.Errorf("toggle chat pin: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// GenerateChatPIN issues a fresh random 4-digit numeric PIN, sets its expiry to
// now + 5 minutes, persists both to the user's record, and returns them.
func (r *PostgresRepo) GenerateChatPIN(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	pin, err := randomPIN()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate chat pin: %w", err)
	}
	expiry := time.Now().Add(chatPINTTL)

	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"chat_pin":        pin,
			"chat_pin_expiry": expiry,
		})
	if result.Error != nil {
		return "", time.Time{}, fmt.Errorf("persist chat pin: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return "", time.Time{}, gorm.ErrRecordNotFound
	}
	return pin, expiry, nil
}

// GetOrRefreshChatPIN returns the user's currently active PIN and expiry, transparently
// generating a new one when none exists or the existing PIN has expired.
func (r *PostgresRepo) GetOrRefreshChatPIN(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Select("chat_pin", "chat_pin_expiry").
		Where("user_id = ?", userID).
		First(&user).Error; err != nil {
		return "", time.Time{}, err
	}
	if user.ChatPIN != "" && time.Now().Before(user.ChatPINExpiry) {
		return user.ChatPIN, user.ChatPINExpiry, nil
	}
	return r.GenerateChatPIN(ctx, userID)
}

// SearchUsersByUsername performs a case-insensitive prefix search over usernames for
// chat discovery. It returns full user records; callers must project only safe fields
// (never the ChatPIN) into their responses. Results are capped by limit.
func (r *PostgresRepo) SearchUsersByUsername(ctx context.Context, query string, limit int) ([]models.User, error) {
	var users []models.User
	if err := r.db.WithContext(ctx).
		Where("username ILIKE ?", query+"%").
		Order("username ASC").
		Limit(limit).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("search users by username: %w", err)
	}
	return users, nil
}

// randomPIN returns a cryptographically random, zero-padded 4-digit numeric string ("0000"-"9999").
func randomPIN() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04d", n.Int64()), nil
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
