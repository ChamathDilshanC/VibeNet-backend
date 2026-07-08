package websocket

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 64 * 1024
	sendBufferSize = 256
)

// inboundMessage is the encrypted payload sent by a connected client over WebSocket.
type inboundMessage struct {
	MessageID  string `json:"message_id"`
	ReceiverID string `json:"receiver_id"`
	ChatRoomID string `json:"chat_room_id"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// outboundMessage is the encrypted payload delivered to a recipient's WebSocket connection.
type outboundMessage struct {
	MessageID  string `json:"message_id"`
	SenderID   string `json:"sender_id"`
	ChatRoomID string `json:"chat_room_id"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// Client represents a single authenticated WebSocket connection bound to a VibeNet user.
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	userID uuid.UUID
	dynamo *db.DynamoRepo
}

// NewClient constructs a Client for the authenticated user and begins read/write pumps.
func NewClient(hub *Hub, conn *websocket.Conn, userID uuid.UUID, dynamo *db.DynamoRepo) *Client {
	client := &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan []byte, sendBufferSize),
		userID: userID,
		dynamo: dynamo,
	}
	hub.Register(client)
	go client.writePump()
	go client.readPump()
	return client
}

// readPump continuously reads encrypted frames from the WebSocket and routes them to recipients.
func (c *Client) readPump() {
	defer func() {
		c.hub.Unregister(c)
		_ = c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("websocket read error for user %s: %v", c.userID, err)
			}
			break
		}
		c.handleMessage(raw)
	}
}

// handleMessage validates an inbound encrypted payload, delivers it to the receiver, and persists it.
func (c *Client) handleMessage(raw []byte) {
	var inbound inboundMessage
	if err := json.Unmarshal(raw, &inbound); err != nil {
		log.Printf("websocket: invalid message payload from user %s", c.userID)
		return
	}

	if inbound.ReceiverID == "" || inbound.ChatRoomID == "" || inbound.Ciphertext == "" || inbound.Nonce == "" {
		log.Printf("websocket: missing required fields from user %s", c.userID)
		return
	}

	receiverID, err := uuid.Parse(inbound.ReceiverID)
	if err != nil {
		log.Printf("websocket: invalid receiver_id from user %s", c.userID)
		return
	}

	if inbound.Timestamp == 0 {
		inbound.Timestamp = time.Now().UnixMilli()
	}
	if inbound.MessageID == "" {
		inbound.MessageID = uuid.NewString()
	}

	outbound := outboundMessage{
		MessageID:  inbound.MessageID,
		SenderID:   c.userID.String(),
		ChatRoomID: inbound.ChatRoomID,
		Ciphertext: inbound.Ciphertext,
		Nonce:      inbound.Nonce,
		Timestamp:  inbound.Timestamp,
	}

	payload, err := json.Marshal(outbound)
	if err != nil {
		log.Printf("websocket: failed to marshal outbound message: %v", err)
		return
	}

	c.hub.DeliverToUser(receiverID, payload)

	go func(messageID, chatRoomID, senderID, ciphertext, nonce string, timestamp int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := c.dynamo.SaveMessage(ctx, messageID, chatRoomID, senderID, ciphertext, nonce, timestamp); err != nil {
			log.Printf("websocket: async dynamodb save failed: %v", err)
		}
	}(inbound.MessageID, inbound.ChatRoomID, c.userID.String(), inbound.Ciphertext, inbound.Nonce, inbound.Timestamp)
}

// writePump sends queued encrypted payloads to the client and maintains connection health via pings.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			writer, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			if _, err := writer.Write(message); err != nil {
				_ = writer.Close()
				return
			}
			if err := writer.Close(); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
