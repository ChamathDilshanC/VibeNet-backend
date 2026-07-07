package models

import "github.com/google/uuid"

// Contact represents a bidirectional relationship entry between two users.
// Each row links a user to one of their contacts in the PostgreSQL contacts table.
type Contact struct {
	UserID    uuid.UUID `gorm:"type:uuid;primaryKey;not null" json:"user_id"`
	ContactID uuid.UUID `gorm:"type:uuid;primaryKey;not null" json:"contact_id"`
}

// TableName overrides the default GORM table name for the Contact model.
func (Contact) TableName() string {
	return "contacts"
}
