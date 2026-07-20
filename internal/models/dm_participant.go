package models

import (
	"time"

	"github.com/google/uuid"
)

// DMParticipant indexes which direct-message rooms a user is party to.
//
// Conversations are otherwise entirely client-side (see the frontend's
// conversations.ts): the room id is a deterministic hash of both user ids,
// and the only way a client normally learns a room exists is by starting it
// itself or receiving a live WebSocket frame for it. A recipient who was
// offline when the other side sent the opening message has no way to ever
// discover that room — this table is the server-side catch-up path (see
// PostgresRepo.RecordDMParticipants and ListDiscoverableDMs).
//
// One row per (chat_room_id, user_id): both participants are written when a
// DM is sent, so either side can look up "which rooms am I in" regardless of
// who sent first.
type DMParticipant struct {
	ChatRoomID string    `gorm:"type:varchar(80);primaryKey;not null" json:"chat_room_id"`
	UserID     uuid.UUID `gorm:"type:uuid;primaryKey;not null" json:"user_id"`
	PeerID     uuid.UUID `gorm:"type:uuid;not null" json:"peer_id"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// TableName overrides the default GORM table name for the DMParticipant model.
func (DMParticipant) TableName() string {
	return "dm_participants"
}
