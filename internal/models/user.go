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
// Anti-spam chat PIN: when ChatPinEnabled is true, a stranger must supply a valid
// 6-digit PIN before they can fetch this user's public key and initiate a chat.
// The PIN is either a "rotating" code (deterministically derived from the user and
// the current 5-minute window — see internal/pin) or a "static" CustomPin the user
// sets. CustomPin is never serialized to clients.
type User struct {
	UserID   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"user_id"`
	Username string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"username"`
	// DisplayName is the human "real name" shown throughout the client in place
	// of the login username. Seeded at sign-up (the username for password
	// accounts, the Google account name for OAuth) and fully editable in profile
	// settings. It carries no uniqueness constraint — two people may share a real
	// name. Clients fall back to Username when it is empty (see toUserSummary).
	DisplayName string  `gorm:"type:varchar(64);not null;default:''" json:"display_name"`
	Email       *string `gorm:"type:varchar(255);uniqueIndex" json:"email,omitempty"`
	// PhoneNumber is captured at password sign-up and, like Email, is unique across
	// accounts. It is a pointer so pre-existing and Google OAuth rows (which never
	// supply one) store NULL rather than colliding on an empty string in the unique
	// index. Never revealed to peers — only serialized back to the owner.
	PhoneNumber  *string   `gorm:"type:varchar(32);uniqueIndex" json:"phone_number,omitempty"`
	GoogleID     *string   `gorm:"type:varchar(255);uniqueIndex" json:"-"`
	PasswordHash *string   `gorm:"type:text" json:"-"`
	PublicKey    *string   `gorm:"type:text" json:"public_key,omitempty"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`

	// AvatarURL is the profile picture shown throughout the client. It is sourced
	// from the Google account photo and re-synced on every Google sign-in, so it
	// tracks changes made in Google. Password accounts have none and fall back to
	// initials rendered client-side.
	AvatarURL *string `gorm:"type:text" json:"avatar_url,omitempty"`

	// ChatPinEnabled gates public-key retrieval behind a chat PIN when true. New
	// accounts default to true (set explicitly at registration — see CreateUser —
	// because GORM can't distinguish an unset bool from a deliberate false).
	ChatPinEnabled bool `gorm:"not null;default:true" json:"chat_pin_enabled"`
	// ChatPinType selects how the required PIN is derived: "rotating" (a code that
	// changes every 5 minutes) or "static" (the user's CustomPin). Defaults to
	// "rotating".
	ChatPinType string `gorm:"type:varchar(16);not null;default:'rotating'" json:"chat_pin_type"`
	// CustomPin is the user's chosen 6-digit static PIN, used only when
	// ChatPinType is "static". Nil until the user sets one. Never serialized.
	CustomPin *string `gorm:"type:varchar(6)" json:"-"`
}

// Chat PIN type values for ChatPinType.
const (
	ChatPinRotating = "rotating"
	ChatPinStatic   = "static"
)

// TableName overrides the default GORM table name for the User model.
func (User) TableName() string {
	return "users"
}
