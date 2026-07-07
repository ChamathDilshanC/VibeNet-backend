// Package models defines the data structures used by VibeNet's persistence layers.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a registered VibeNet account stored in PostgreSQL.
// The PublicKey field holds the client's E2EE public key; the server never
// stores or receives the corresponding private key.
type User struct {
	UserID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"user_id"`
	Username     string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"type:text;not null" json:"-"`
	PublicKey    string    `gorm:"type:text;not null" json:"public_key"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// TableName overrides the default GORM table name for the User model.
func (User) TableName() string {
	return "users"
}
