// Package db provides database connection and lifecycle management for
// VibeNet. All persistence — relational metadata and encrypted message
// history alike — lives in one PostgreSQL database.
package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// ErrInvalidPinType is returned by UpdatePinSettings for an unknown pin type.
var ErrInvalidPinType = errors.New("invalid chat pin type")

// ErrUsernameTaken is returned when a profile update would collide with the
// username of another account. Callers should map this to 409.
var ErrUsernameTaken = errors.New("username already taken")

// ErrEmailTaken and ErrPhoneTaken are returned by CreateUser when the requested
// email or phone number already belongs to another account. They are distinct so
// the API layer can tell the caller exactly which field collided. Map both to 409.
var (
	ErrEmailTaken = errors.New("email already registered")
	ErrPhoneTaken = errors.New("phone number already registered")
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

	if err := database.AutoMigrate(
		&models.User{},
		&models.Contact{},
		&models.Group{},
		&models.GroupMember{},
		&models.GroupInvite{},
		&models.DMParticipant{},
		&models.Message{},
	); err != nil {
		return nil, fmt.Errorf("auto-migrate postgres schema: %w", err)
	}

	return database, nil
}

// NewPostgresRepo returns a repository backed by the provided GORM handle.
func NewPostgresRepo(database *gorm.DB) *PostgresRepo {
	return &PostgresRepo{db: database}
}

// CreateUser inserts a new standard-registration user with a bcrypt password hash and E2EE public key.
//
// Before inserting, it checks whether the email or phone number is already taken and
// returns ErrEmailTaken / ErrPhoneTaken so the caller can report the exact collision.
// The pre-check is best-effort for a friendly message; the unique indexes on email and
// phone_number remain the source of truth and back-stop the race between check and write
// (a concurrent duplicate surfaces as isUniqueViolation below).
func (r *PostgresRepo) CreateUser(ctx context.Context, username, passwordHash, publicKey string, email, phoneNumber *string) (*models.User, error) {
	if email != nil {
		var count int64
		if err := r.db.WithContext(ctx).Model(&models.User{}).
			Where("email = ?", *email).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("check email availability: %w", err)
		}
		if count > 0 {
			return nil, ErrEmailTaken
		}
	}
	if phoneNumber != nil {
		var count int64
		if err := r.db.WithContext(ctx).Model(&models.User{}).
			Where("phone_number = ?", *phoneNumber).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("check phone availability: %w", err)
		}
		if count > 0 {
			return nil, ErrPhoneTaken
		}
	}

	user := &models.User{
		Username: username,
		// Password accounts have no external "real name" source, so the username
		// doubles as the initial display name. It stays fully editable in settings.
		DisplayName:  username,
		Email:        email,
		PhoneNumber:  phoneNumber,
		PasswordHash: &passwordHash,
		PublicKey:    &publicKey,
		// Chat PIN protection is on by default with a rotating code. Set explicitly
		// rather than relying on the column default: GORM can't tell an unset bool
		// from a deliberate false, so it would otherwise insert false.
		ChatPinEnabled: true,
		ChatPinType:    models.ChatPinRotating,
		Status:         models.UserStatusActive,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		// Lost the race with a concurrent registration: the unique index rejected
		// the row. We can't tell which column collided from the driver message, so
		// report the email conflict — the far more common case at sign-up.
		if isUniqueViolation(err) {
			return nil, ErrEmailTaken
		}
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
func (r *PostgresRepo) CreateOrGetUserByGoogle(ctx context.Context, googleID, email, username, displayName, avatarURL string) (*models.User, error) {
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
		// Backfill a missing display name (e.g. accounts created before this
		// column existed) from the Google name, but never overwrite one the
		// person has since set — renaming in Google must not clobber it.
		if existing.DisplayName == "" && displayName != "" {
			if err := r.db.WithContext(ctx).Model(&existing).
				Update("display_name", displayName).Error; err != nil {
				log.Printf("backfill display name for %s: %v", existing.UserID, err)
			} else {
				existing.DisplayName = displayName
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
		Username:    username,
		DisplayName: displayName,
		Email:       &emailCopy,
		GoogleID:    &googleIDCopy,
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
//
// Uniqueness is checked case-insensitively so "ChamathDilshanC" and
// "chamathdilshanc" cannot both exist — this matches the case-insensitive
// username search (SearchUsersByUsername) and blocks look-alike impersonation
// that the case-sensitive DB unique index alone would let through. The index
// remains as a race backstop between this check and the write.
func (r *PostgresRepo) UpdateProfile(ctx context.Context, userID uuid.UUID, username, displayName string) (*models.User, error) {
	var conflicts int64
	if err := r.db.WithContext(ctx).Model(&models.User{}).
		Where("LOWER(username) = LOWER(?) AND user_id <> ?", username, userID).
		Count(&conflicts).Error; err != nil {
		return nil, fmt.Errorf("check username availability: %w", err)
	}
	if conflicts > 0 {
		return nil, ErrUsernameTaken
	}

	// Username and display name move together in a single write. display_name has
	// no uniqueness constraint, so only the username can collide (guarded above +
	// the unique-index backstop below).
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"username":     username,
			"display_name": displayName,
		})
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

// UpdateAvatarURL sets the user's profile picture URL after an avatar upload and
// returns the refreshed record so the caller can broadcast and echo back the full
// profile. A missing user yields gorm.ErrRecordNotFound.
func (r *PostgresRepo) UpdateAvatarURL(ctx context.Context, userID uuid.UUID, avatarURL string) (*models.User, error) {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Update("avatar_url", avatarURL)
	if result.Error != nil {
		return nil, fmt.Errorf("update avatar url: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		// Each upload writes a fresh UUID URL, so an unchanged value never happens
		// here — zero rows means the user is gone.
		return nil, gorm.ErrRecordNotFound
	}
	return r.GetUserByID(ctx, userID)
}

// UpdateLastSeen stamps the user's last-seen time (called by the websocket hub when
// their connection drops). Best-effort presence metadata: a missing user is not an
// error worth surfacing, so zero rows affected is reported as gorm.ErrRecordNotFound
// only for the caller to log, not to treat as fatal.
func (r *PostgresRepo) UpdateLastSeen(ctx context.Context, userID uuid.UUID, t time.Time) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Update("last_seen", t)
	if result.Error != nil {
		return fmt.Errorf("update last seen: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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

// GetPublicKey returns the E2EE public key for a user, used by peers before encrypting
// messages, along with the user's avatar URL so the caller can show a real profile
// picture for the peer rather than only initials, and their account status so a
// caller with an existing conversation can reflect a deactivated/deleted peer.
//
// The chat PIN is single-sided: fetching a peer's key is never gated by the peer's
// PIN. The current user unlocks the chat interface with their own PIN on the client
// (verified via POST /api/user/verify-pin), so this simply returns the key.
//
// A missing public key is only ErrRecordNotFound for an active/deactivated account
// (one that simply hasn't published a key yet — new-chat lookups should 404). A
// deleted account has its key wiped by DeleteUser, so an empty key there is expected
// and still returns successfully: the caller needs the status to update an existing
// conversation's UI even though there is no key left to encrypt new messages with.
func (r *PostgresRepo) GetPublicKey(ctx context.Context, userID uuid.UUID) (string, *string, string, *time.Time, string, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Select("username", "display_name", "public_key", "avatar_url", "last_seen", "status").
		Where("user_id = ?", userID).
		First(&user).Error; err != nil {
		return "", nil, "", nil, "", err
	}

	hasKey := user.PublicKey != nil && *user.PublicKey != ""
	if !hasKey && user.Status != models.UserStatusDeleted {
		return "", nil, "", nil, "", gorm.ErrRecordNotFound
	}
	publicKey := ""
	if hasKey {
		publicKey = *user.PublicKey
	}
	return publicKey, user.AvatarURL, displayNameOf(&user), user.LastSeen, user.Status, nil
}

// displayNameOf returns a user's display name, falling back to the username when
// none has been set (e.g. rows predating the display_name column). Every caller
// that surfaces a name to a client should route through this so the UI never
// shows an empty label.
func displayNameOf(user *models.User) string {
	if strings.TrimSpace(user.DisplayName) != "" {
		return user.DisplayName
	}
	return user.Username
}

// UpdatePinSettings persists the authenticated user's chat-PIN configuration and
// returns the refreshed record. pinType must be models.ChatPinRotating or
// models.ChatPinStatic (else ErrInvalidPinType). customPin is written only for the
// static type; passing nil there leaves any existing custom PIN untouched, so a user
// can toggle back to static without re-entering it. Rotating codes are computed, not
// stored, so nothing else needs persisting.
func (r *PostgresRepo) UpdatePinSettings(ctx context.Context, userID uuid.UUID, enabled bool, pinType string, customPin *string) (*models.User, error) {
	if pinType != models.ChatPinRotating && pinType != models.ChatPinStatic {
		return nil, ErrInvalidPinType
	}

	updates := map[string]interface{}{
		"chat_pin_enabled": enabled,
		"chat_pin_type":    pinType,
	}
	if pinType == models.ChatPinStatic && customPin != nil {
		updates["custom_pin"] = *customPin
	}

	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Updates(updates)
	if result.Error != nil {
		return nil, fmt.Errorf("update pin settings: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		// RowsAffected is also 0 when nothing changed; confirm existence by reading back.
		return r.GetUserByID(ctx, userID)
	}
	return r.GetUserByID(ctx, userID)
}

// SearchUsersByUsername performs a case-insensitive prefix search over usernames for
// chat discovery. It returns full user records; callers must project only safe fields
// (never CustomPin) into their responses. Results are capped by limit.
//
// Only active accounts are discoverable — a deactivated account shouldn't gain new
// conversations while signed out of one, and a deleted account has nothing left worth
// finding.
func (r *PostgresRepo) SearchUsersByUsername(ctx context.Context, query string, limit int) ([]models.User, error) {
	var users []models.User
	if err := r.db.WithContext(ctx).
		Where("username ILIKE ? AND status = ?", query+"%", models.UserStatusActive).
		Order("username ASC").
		Limit(limit).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("search users by username: %w", err)
	}
	return users, nil
}

// RecordDMParticipants idempotently indexes both sides of a direct-message
// room so either participant's client can later discover it — see
// ListDiscoverableDMs. Safe to call on every message sent in the room:
// ON CONFLICT DO NOTHING makes repeat calls for an already-known room a
// no-op.
func (r *PostgresRepo) RecordDMParticipants(ctx context.Context, chatRoomID string, userA, userB uuid.UUID) error {
	rows := []models.DMParticipant{
		{ChatRoomID: chatRoomID, UserID: userA, PeerID: userB},
		{ChatRoomID: chatRoomID, UserID: userB, PeerID: userA},
	}
	if err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&rows).Error; err != nil {
		return fmt.Errorf("record dm participants: %w", err)
	}
	return nil
}

// DiscoverableDM is one row of ListDiscoverableDMs: a DM room the queried
// user is a participant in, joined with enough of the peer's profile for the
// caller to materialize a full local conversation without a second round
// trip per peer.
type DiscoverableDM struct {
	ChatRoomID  string
	PeerID      uuid.UUID
	Username    string
	DisplayName string
	AvatarURL   *string
	PublicKey   *string
	Status      string
}

// ListDiscoverableDMs lists every DM room userID is a participant in per the
// server-side index (see RecordDMParticipants), newest first. This is the
// catch-up path for a first-contact conversation someone else opened while
// this user's device was offline — the WebSocket hub only delivers live and
// there is otherwise no server-side "conversations" list at all.
func (r *PostgresRepo) ListDiscoverableDMs(ctx context.Context, userID uuid.UUID) ([]DiscoverableDM, error) {
	var rows []DiscoverableDM
	if err := r.db.WithContext(ctx).
		Table("dm_participants AS dm").
		Select("dm.chat_room_id AS chat_room_id, dm.peer_id AS peer_id, u.username AS username, u.display_name AS display_name, u.avatar_url AS avatar_url, u.public_key AS public_key, u.status AS status").
		Joins("JOIN users u ON u.user_id = dm.peer_id").
		Where("dm.user_id = ?", userID).
		Order("dm.created_at DESC").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("list discoverable dms: %w", err)
	}
	return rows, nil
}

// DeactivateUser flips the account to "deactivated": it can no longer obtain a JWT
// (see Login / GoogleCallback), but every column is left intact so the profile and
// past messages keep displaying normally to peers (with a "Deactivated" badge) and
// the account can be brought back by whatever reactivation path is added later.
func (r *PostgresRepo) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Update("status", models.UserStatusDeactivated)
	if result.Error != nil {
		return fmt.Errorf("deactivate user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// DeleteUser soft-deletes the account: status becomes "deleted", every
// personally-identifying column is scrubbed, and the account can never sign in again
// (password hash and Google linkage are cleared too, so a re-registration under the
// same email/Google account isn't blocked by this row). UserID and Username are left
// untouched — UserID because messages key off it as an immutable foreign key,
// Username because it still carries a unique index and nothing requires it back.
// Existing peers resolve the account to "Deleted User" client-side from the status
// field, not from these now-blank columns.
func (r *PostgresRepo) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"status":           models.UserStatusDeleted,
			"display_name":     "",
			"email":            nil,
			"phone_number":     nil,
			"avatar_url":       nil,
			"google_id":        nil,
			"password_hash":    nil,
			"public_key":       nil,
			"custom_pin":       nil,
			"chat_pin_enabled": false,
		})
	if result.Error != nil {
		return fmt.Errorf("delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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
