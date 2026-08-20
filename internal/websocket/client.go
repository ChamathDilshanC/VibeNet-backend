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

// Frame types exchanged over the WebSocket. The Type field discriminates chat
// messages from delivery/read control frames; an empty type is treated as a
// chat message for backward compatibility.
const (
	frameMessage        = "message"
	frameAck            = "ack"
	frameRead           = "read"
	framePresence       = "presence"
	frameTyping         = "typing"
	framePresenceUpdate = "presence_update"
	framePin            = "pin_message"
	frameUnpin          = "unpin_message"
)

// inboundMessage is a frame sent by a connected client. For a chat message it
// carries the encrypted payload; for a "read" frame only Type, ReceiverID (the
// original sender to notify) and ChatRoomID are used; for a "presence" frame
// only Type and UserIDs (the peers whose online state is being queried).
//
// GroupID switches a "message", "typing", "pin_message", or "unpin_message"
// frame into group-room mode: instead of routing to a single ReceiverID, the
// hub fans the frame out to every member of the group (except the sender).
// ReceiverID is ignored on group frames.
type inboundMessage struct {
	Type       string   `json:"type"`
	MessageID  string   `json:"message_id"`
	ReceiverID string   `json:"receiver_id"`
	GroupID    string   `json:"group_id"`
	ChatRoomID string   `json:"chat_room_id"`
	Ciphertext string   `json:"ciphertext"`
	Nonce      string   `json:"nonce"`
	Timestamp  int64    `json:"timestamp"`
	UserIDs    []string `json:"user_ids"`
	// IsTyping is set on a "typing" frame: true while the sender is composing,
	// false when they stop. Routed to the receiver like a read receipt.
	IsTyping bool `json:"is_typing"`
}

// outboundMessage is the encrypted payload delivered to a recipient's WebSocket
// connection. GroupID is set only on group-room messages.
type outboundMessage struct {
	Type       string `json:"type"`
	MessageID  string `json:"message_id"`
	SenderID   string `json:"sender_id"`
	GroupID    string `json:"group_id,omitempty"`
	ChatRoomID string `json:"chat_room_id"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// ackFrame tells the original sender whether their message reached an online
// recipient (delivered=true) or only reached the server (delivered=false).
type ackFrame struct {
	Type       string `json:"type"`
	MessageID  string `json:"message_id"`
	ChatRoomID string `json:"chat_room_id"`
	Delivered  bool   `json:"delivered"`
}

// readFrame tells the original sender that the recipient has read the messages
// in a chat room — the WhatsApp-style blue double tick.
type readFrame struct {
	Type       string `json:"type"`
	ChatRoomID string `json:"chat_room_id"`
	ReaderID   string `json:"reader_id"`
}

// presenceFrame answers a presence query with the subset of the requested user
// IDs that currently have a live connection to this hub.
type presenceFrame struct {
	Type   string   `json:"type"`
	Online []string `json:"online"`
}

// typingFrame is routed to the receiver when a peer starts/stops composing, so
// their client can show or hide the typing indicator for the sender. In a group
// room it fans out to every member and GroupID identifies which group header
// should show "<sender> is typing…".
type typingFrame struct {
	Type       string `json:"type"`
	SenderID   string `json:"sender_id"`
	GroupID    string `json:"group_id,omitempty"`
	ChatRoomID string `json:"chat_room_id"`
	IsTyping   bool   `json:"is_typing"`
}

// pinFrame is routed to the DM peer, or fanned out to every group member, when
// a participant pins or unpins a message for the whole room — Type alone
// (pin_message vs unpin_message) is the signal; there is no content to carry.
type pinFrame struct {
	Type       string `json:"type"`
	MessageID  string `json:"message_id"`
	GroupID    string `json:"group_id,omitempty"`
	ChatRoomID string `json:"chat_room_id"`
}

// presenceUpdateFrame is broadcast when a user connects or disconnects, so peers
// update their online/last-seen display immediately rather than waiting for the
// next presence poll. LastSeen (unix ms) is set only on the offline transition.
type presenceUpdateFrame struct {
	Type     string `json:"type"`
	UserID   string `json:"user_id"`
	IsOnline bool   `json:"is_online"`
	LastSeen *int64 `json:"last_seen,omitempty"`
}

// Client represents a single authenticated WebSocket connection bound to a VibeNet user.
type Client struct {
	hub      *Hub
	conn     *websocket.Conn
	send     chan []byte
	userID   uuid.UUID
	messages *db.MessageRepo
}

// NewClient constructs a Client for the authenticated user and begins read/write pumps.
func NewClient(hub *Hub, conn *websocket.Conn, userID uuid.UUID, messages *db.MessageRepo) *Client {
	client := &Client{
		hub:      hub,
		conn:     conn,
		send:     make(chan []byte, sendBufferSize),
		userID:   userID,
		messages: messages,
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

// handleMessage decodes an inbound frame and dispatches it by type: a chat
// message is routed and persisted, a read receipt is forwarded to the sender.
func (c *Client) handleMessage(raw []byte) {
	var inbound inboundMessage
	if err := json.Unmarshal(raw, &inbound); err != nil {
		log.Printf("websocket: invalid frame from user %s: %v", c.userID, err)
		return
	}

	switch inbound.Type {
	case frameRead:
		c.handleReadReceipt(inbound)
	case framePresence:
		c.handlePresence(inbound)
	case frameTyping:
		c.handleTyping(inbound)
	case framePin, frameUnpin:
		c.handlePinToggle(inbound, inbound.Type)
	default: // frameMessage or empty (backward compatible)
		c.handleChatMessage(inbound)
	}
}

// handleTyping forwards a composing/stopped signal so recipients can toggle the
// typing indicator. Carries no content — purely a UI hint. With a group_id the
// signal fans out to every group member instead of a single receiver.
func (c *Client) handleTyping(inbound inboundMessage) {
	if inbound.GroupID != "" {
		c.handleGroupTyping(inbound)
		return
	}
	if inbound.ReceiverID == "" || inbound.ChatRoomID == "" {
		return
	}
	receiverID, err := uuid.Parse(inbound.ReceiverID)
	if err != nil {
		log.Printf("websocket: invalid receiver_id %q on typing frame from user %s", inbound.ReceiverID, c.userID)
		return
	}

	payload, err := json.Marshal(typingFrame{
		Type:       frameTyping,
		SenderID:   c.userID.String(),
		ChatRoomID: inbound.ChatRoomID,
		IsTyping:   inbound.IsTyping,
	})
	if err != nil {
		return
	}
	c.hub.DeliverToUser(receiverID, payload)
}

// handleGroupTyping fans a typing signal out to the sender's fellow group
// members, after confirming the sender actually belongs to the group.
func (c *Client) handleGroupTyping(inbound inboundMessage) {
	groupID, err := uuid.Parse(inbound.GroupID)
	if err != nil {
		log.Printf("websocket: invalid group_id %q on typing frame from user %s", inbound.GroupID, c.userID)
		return
	}
	if !c.hub.IsGroupMemberCached(groupID, c.userID) {
		return
	}

	payload, err := json.Marshal(typingFrame{
		Type:       frameTyping,
		SenderID:   c.userID.String(),
		GroupID:    inbound.GroupID,
		ChatRoomID: groupChatRoomID(groupID),
		IsTyping:   inbound.IsTyping,
	})
	if err != nil {
		return
	}
	c.hub.DeliverToGroup(groupID, c.userID, payload)
}

// handlePinToggle forwards a pin/unpin signal so the shared pinned state stays
// in sync everywhere the message lives — the DM peer, or every member of a
// group. Carries no content: the sender's own local mirror is already set by
// the time this fires, so this only notifies everyone else. frameType selects
// pin_message or unpin_message on the outbound frame.
func (c *Client) handlePinToggle(inbound inboundMessage, frameType string) {
	if inbound.MessageID == "" {
		return
	}
	if inbound.GroupID != "" {
		c.handleGroupPinToggle(inbound, frameType)
		return
	}
	if inbound.ReceiverID == "" || inbound.ChatRoomID == "" {
		return
	}
	receiverID, err := uuid.Parse(inbound.ReceiverID)
	if err != nil {
		log.Printf("websocket: invalid receiver_id %q on %s frame from user %s", inbound.ReceiverID, frameType, c.userID)
		return
	}

	payload, err := json.Marshal(pinFrame{
		Type:       frameType,
		MessageID:  inbound.MessageID,
		ChatRoomID: inbound.ChatRoomID,
	})
	if err != nil {
		return
	}
	c.hub.DeliverToUser(receiverID, payload)
}

// handleGroupPinToggle fans a pin/unpin signal out to the sender's fellow
// group members, after confirming the sender actually belongs to the group.
func (c *Client) handleGroupPinToggle(inbound inboundMessage, frameType string) {
	groupID, err := uuid.Parse(inbound.GroupID)
	if err != nil {
		log.Printf("websocket: invalid group_id %q on %s frame from user %s", inbound.GroupID, frameType, c.userID)
		return
	}
	if !c.hub.IsGroupMemberCached(groupID, c.userID) {
		return
	}

	payload, err := json.Marshal(pinFrame{
		Type:       frameType,
		MessageID:  inbound.MessageID,
		GroupID:    inbound.GroupID,
		ChatRoomID: groupChatRoomID(groupID),
	})
	if err != nil {
		return
	}
	c.hub.DeliverToGroup(groupID, c.userID, payload)
}

// handlePresence answers a presence query: of the requested user IDs, report
// back the ones that currently have a live WebSocket connection to this hub.
func (c *Client) handlePresence(inbound inboundMessage) {
	online := make([]string, 0, len(inbound.UserIDs))
	for _, id := range inbound.UserIDs {
		uid, err := uuid.Parse(id)
		if err != nil {
			continue
		}
		if c.hub.IsOnline(uid) {
			online = append(online, id)
		}
	}
	c.trySend(presenceFrame{Type: framePresence, Online: online})
}

// handleReadReceipt forwards a recipient's "I've read this chat" signal to the
// original sender so their sent messages can flip to the blue double tick.
func (c *Client) handleReadReceipt(inbound inboundMessage) {
	if inbound.ReceiverID == "" || inbound.ChatRoomID == "" {
		return
	}
	senderID, err := uuid.Parse(inbound.ReceiverID)
	if err != nil {
		log.Printf("websocket: invalid receiver_id %q on read receipt from user %s", inbound.ReceiverID, c.userID)
		return
	}

	payload, err := json.Marshal(readFrame{
		Type:       frameRead,
		ChatRoomID: inbound.ChatRoomID,
		ReaderID:   c.userID.String(),
	})
	if err != nil {
		return
	}
	c.hub.DeliverToUser(senderID, payload)
}

// groupChatRoomID derives the canonical message-room id for a group. Derived
// server-side from the authenticated frame's group_id — never taken from the
// client's chat_room_id — so a member can't write into another room's history.
func groupChatRoomID(groupID uuid.UUID) string {
	return "group:" + groupID.String()
}

// handleGroupChatMessage validates an inbound group payload, fans it out to
// every other member, acks the sender, and persists it once under the group's
// room id. Delivery follows the same best-effort contract as 1:1 messages —
// offline members catch up from history (GET /api/messages/group:<id>).
func (c *Client) handleGroupChatMessage(inbound inboundMessage) {
	if inbound.Ciphertext == "" || inbound.Nonce == "" {
		log.Printf("websocket: missing required fields on group message from user %s", c.userID)
		return
	}
	groupID, err := uuid.Parse(inbound.GroupID)
	if err != nil {
		log.Printf("websocket: invalid group_id %q from user %s: %v", inbound.GroupID, c.userID, err)
		return
	}
	// Only members may post into a group room.
	if !c.hub.IsGroupMemberCached(groupID, c.userID) {
		log.Printf("websocket: user %s is not a member of group %s, dropping message", c.userID, groupID)
		return
	}

	if inbound.Timestamp == 0 {
		inbound.Timestamp = time.Now().UnixMilli()
	}
	if inbound.MessageID == "" {
		inbound.MessageID = uuid.NewString()
	}
	chatRoomID := groupChatRoomID(groupID)

	payload, err := json.Marshal(outboundMessage{
		Type:       frameMessage,
		MessageID:  inbound.MessageID,
		SenderID:   c.userID.String(),
		GroupID:    inbound.GroupID,
		ChatRoomID: chatRoomID,
		Ciphertext: inbound.Ciphertext,
		Nonce:      inbound.Nonce,
		Timestamp:  inbound.Timestamp,
	})
	if err != nil {
		log.Printf("websocket: failed to marshal outbound group message: %v", err)
		return
	}

	// delivered flips the sender's tick to double as soon as ANY member
	// received the fan-out — the closest group analogue of the 1:1 ack.
	delivered := c.hub.DeliverToGroup(groupID, c.userID, payload)
	c.trySend(ackFrame{
		Type:       frameAck,
		MessageID:  inbound.MessageID,
		ChatRoomID: chatRoomID,
		Delivered:  delivered > 0,
	})

	go func(messageID, chatRoomID, senderID, ciphertext, nonce string, timestamp int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := c.messages.SaveMessage(ctx, messageID, chatRoomID, senderID, ciphertext, nonce, timestamp); err != nil {
			log.Printf("websocket: async message save failed for group message %s: %v", messageID, err)
		}
	}(inbound.MessageID, chatRoomID, c.userID.String(), inbound.Ciphertext, inbound.Nonce, inbound.Timestamp)
}

// handleChatMessage validates an inbound encrypted payload, delivers it to the
// receiver, acknowledges delivery back to the sender, and persists it. Frames
// carrying a group_id are routed to the whole group room instead.
func (c *Client) handleChatMessage(inbound inboundMessage) {
	if inbound.GroupID != "" {
		c.handleGroupChatMessage(inbound)
		return
	}
	if inbound.ReceiverID == "" || inbound.ChatRoomID == "" || inbound.Ciphertext == "" || inbound.Nonce == "" {
		log.Printf("websocket: missing required fields from user %s", c.userID)
		return
	}

	receiverID, err := uuid.Parse(inbound.ReceiverID)
	if err != nil {
		log.Printf("websocket: invalid receiver_id %q from user %s: %v", inbound.ReceiverID, c.userID, err)
		return
	}

	if inbound.Timestamp == 0 {
		inbound.Timestamp = time.Now().UnixMilli()
	}
	if inbound.MessageID == "" {
		inbound.MessageID = uuid.NewString()
	}

	outbound := outboundMessage{
		Type:       frameMessage,
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

	// delivered is true only when the receiver has a live connection and the
	// message was queued to it — this is the single-tick vs double-tick signal.
	delivered := c.hub.DeliverToUser(receiverID, payload)
	c.trySend(ackFrame{
		Type:       frameAck,
		MessageID:  inbound.MessageID,
		ChatRoomID: inbound.ChatRoomID,
		Delivered:  delivered,
	})

	go func(messageID, chatRoomID, senderID, ciphertext, nonce string, timestamp int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := c.messages.SaveMessage(ctx, messageID, chatRoomID, senderID, ciphertext, nonce, timestamp); err != nil {
			log.Printf("websocket: async message save failed for message %s: %v", messageID, err)
		}
	}(inbound.MessageID, inbound.ChatRoomID, c.userID.String(), inbound.Ciphertext, inbound.Nonce, inbound.Timestamp)

	// Index both sides of the room so the receiver can discover it later even
	// if they weren't connected just now to get it live (see
	// Hub.RecordDMParticipants). Only needed once per room, but the upsert is
	// idempotent so there's no reason to special-case "first message only".
	go c.hub.RecordDMParticipants(inbound.ChatRoomID, c.userID, receiverID)
}

// trySend queues a control frame (ack/read) to this client without blocking:
// if the buffer is full the frame is dropped, since ticks are best-effort.
func (c *Client) trySend(v any) {
	payload, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case c.send <- payload:
	default:
	}
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
