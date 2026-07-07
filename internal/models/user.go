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
type User struct {
	UserID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"user_id"`
	Username     string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"username"`
	Email        *string   `gorm:"type:varchar(255);uniqueIndex" json:"email,omitempty"`
	GoogleID     *string   `gorm:"type:varchar(255);uniqueIndex" json:"-"`
	PasswordHash *string   `gorm:"type:text" json:"-"`
	PublicKey    *string   `gorm:"type:text" json:"public_key,omitempty"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// TableName overrides the default GORM table name for the User model.
func (User) TableName() string {
	return "users"
}
