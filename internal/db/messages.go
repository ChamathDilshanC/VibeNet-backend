package db

import (
	"context"
	"fmt"
	"sort"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MessageRepo persists encrypted chat messages in Postgres, on the same
// connection as the rest of VibeNet's relational data — see models.Message
// for why ChatRoomID+Timestamp form the primary key.
type MessageRepo struct {
	db *gorm.DB
}

// NewMessageRepo returns a repository backed by the provided GORM handle.
func NewMessageRepo(database *gorm.DB) *MessageRepo {
	return &MessageRepo{db: database}
}

// SaveMessage persists an encrypted chat message. Only ciphertext and
// cryptographic metadata are stored; the backend never handles plain-text
// content. A repeat call with the same chatRoomID+timestamp overwrites the
// existing row in place, matching the DynamoDB PutItem semantics this
// replaced.
func (r *MessageRepo) SaveMessage(
	ctx context.Context,
	messageID, chatRoomID, senderID, ciphertext, nonce string,
	timestamp int64,
) error {
	message := models.Message{
		ChatRoomID: chatRoomID,
		Timestamp:  timestamp,
		MessageID:  messageID,
		SenderID:   senderID,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}

	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "chat_room_id"}, {Name: "timestamp"}},
		DoUpdates: clause.AssignmentColumns([]string{"message_id", "sender_id", "ciphertext", "nonce"}),
	}).Create(&message).Error
	if err != nil {
		return fmt.Errorf("save message: %w", err)
	}
	return nil
}

// GetMessages fetches encrypted messages for a chat room. It queries newest
// first (so a limit caps at the most recent N) then re-sorts ascending for
// the caller — the same two-phase shape the DynamoDB query this replaced
// used, kept identical for behavioral parity.
func (r *MessageRepo) GetMessages(ctx context.Context, chatRoomID string, limit int32) ([]models.Message, error) {
	if limit <= 0 {
		limit = 50
	}

	var messages []models.Message
	if err := r.db.WithContext(ctx).
		Where("chat_room_id = ?", chatRoomID).
		Order("timestamp DESC").
		Limit(int(limit)).
		Find(&messages).Error; err != nil {
		return nil, fmt.Errorf("query messages: %w", err)
	}

	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})

	return messages, nil
}
