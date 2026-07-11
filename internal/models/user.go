// Package models defines the data structures used by VibeNet's persistence layers.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a registered VibeNet account stored in PostgreSQL.
// Standard users authenticate with a password hash; Google OAuth users may omit
// a password and initially omit a public key until the client generates E2EE keys.
// The server never stores or receives private keys.
//
// Anti-spam rotating PIN: when RequireChatPIN is enabled, strangers must supply a
// valid, unexpired 4-digit ChatPIN before they can fetch this user's public key
// and initiate a chat. ChatPIN and ChatPINExpiry are never serialized to clients.
type User struct {
	UserID   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"user_id"`
	Username string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"username"`
	// DisplayName is the human "real name" shown throughout the client in place
	// of the login username. Seeded at sign-up (the username for password
	// accounts, the Google account name for OAuth) and fully editable in profile
	// settings. It carries no uniqueness constraint — two people may share a real
	// name. Clients fall back to Username when it is empty (see toUserSummary).
	DisplayName  string    `gorm:"type:varchar(64);not null;default:''" json:"display_name"`
	Email        *string   `gorm:"type:varchar(255);uniqueIndex" json:"email,omitempty"`
	GoogleID     *string   `gorm:"type:varchar(255);uniqueIndex" json:"-"`
	PasswordHash *string   `gorm:"type:text" json:"-"`
	PublicKey    *string   `gorm:"type:text" json:"public_key,omitempty"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`

	// AvatarURL is the profile picture shown throughout the client. It is sourced
	// from the Google account photo and re-synced on every Google sign-in, so it
	// tracks changes made in Google. Password accounts have none and fall back to
	// initials rendered client-side.
	AvatarURL *string `gorm:"type:text" json:"avatar_url,omitempty"`

	// RequireChatPIN gates public-key retrieval behind a rotating PIN when true.
	RequireChatPIN bool `gorm:"not null;default:false" json:"require_chat_pin"`
	// ChatPIN is the current 4-digit numeric PIN; empty when none has been issued.
	ChatPIN string `gorm:"type:varchar(4)" json:"-"`
	// ChatPINExpiry marks when the current ChatPIN stops being valid (issue time + 5m).
	ChatPINExpiry time.Time `json:"-"`
}

// TableName overrides the default GORM table name for the User model.
func (User) TableName() string {
	return "users"
}
