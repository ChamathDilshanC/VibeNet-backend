package models

// Message is an encrypted chat message. The backend acts as a blind router:
// only ciphertext and cryptographic metadata are persisted, plain-text
// content never reaches the server.
//
// ChatRoomID + Timestamp form the primary key, mirroring the partition/sort
// key design of the DynamoDB table this replaced — a repeat SaveMessage call
// with the same pair overwrites in place (see MessageRepo.SaveMessage's
// upsert), rather than introducing a new uniqueness constraint on MessageID
// that didn't exist before.
type Message struct {
	ChatRoomID string `gorm:"column:chat_room_id;primaryKey" json:"chat_room_id"`
	Timestamp  int64  `gorm:"column:timestamp;primaryKey" json:"timestamp"`

	MessageID  string `gorm:"column:message_id;index" json:"message_id"`
	SenderID   string `gorm:"column:sender_id" json:"sender_id"`
	Ciphertext string `gorm:"column:ciphertext" json:"ciphertext"`
	Nonce      string `gorm:"column:nonce" json:"nonce"`
}
