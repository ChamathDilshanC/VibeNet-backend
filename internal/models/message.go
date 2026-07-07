package models

// Message represents an encrypted chat message stored in Amazon DynamoDB.
// The backend acts as a blind router: only ciphertext and cryptographic metadata
// are persisted; plain-text content never reaches the server.
type Message struct {
	// ChatRoomID is the DynamoDB partition key (chat room or sender/receiver pair).
	ChatRoomID string `dynamodbav:"chat_room_id" json:"chat_room_id"`

	// Timestamp is the DynamoDB sort key, stored as a Unix epoch in milliseconds.
	Timestamp int64 `dynamodbav:"timestamp" json:"timestamp"`

	MessageID  string `dynamodbav:"message_id" json:"message_id"`
	SenderID   string `dynamodbav:"sender_id" json:"sender_id"`
	Ciphertext string `dynamodbav:"ciphertext" json:"ciphertext"`
	Nonce      string `dynamodbav:"nonce" json:"nonce"`
}
