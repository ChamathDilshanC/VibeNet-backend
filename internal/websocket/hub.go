// Package websocket implements real-time encrypted message routing for VibeNet.
// The hub acts as a blind router: it forwards ciphertext only and never inspects message content.
package websocket

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/google/uuid"
)

// Hub maintains active WebSocket connections and routes encrypted payloads between clients.
type Hub struct {
	clients    map[uuid.UUID]*Client
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	// postgres stamps last_seen when a user disconnects. Optional (nil in tests):
	// presence broadcasts still fire, only the DB write is skipped.
	postgres *db.PostgresRepo
}

// NewHub creates and starts a Hub event loop in a background goroutine. postgres
// may be nil (e.g. in tests) to skip last-seen persistence.
func NewHub(postgres *db.PostgresRepo) *Hub {
	hub := &Hub{
		clients:    make(map[uuid.UUID]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		postgres:   postgres,
	}
	go hub.run()
	return hub
}

// run processes client registration and disconnection events sequentially.
func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if existing, ok := h.clients[client.userID]; ok {
				// Close only the connection here, not existing.send: DeliverToUser
				// may be concurrently writing to that channel from another
				// goroutine, and closing a channel a concurrent sender can still
				// write to is a "send on closed channel" panic waiting to happen.
				// Closing the conn makes the old client's own readPump/writePump
				// notice and unwind (and unregister) on their own.
				_ = existing.conn.Close()
				log.Printf("websocket: user %s reconnected, closed previous connection", client.userID)
			}
			h.clients[client.userID] = client
			h.mu.Unlock()
			log.Printf("websocket: user %s connected (registered in hub)", client.userID)
			// Tell peers this user just came online, so their header flips to
			// "Online" instantly instead of on the next presence poll.
			go h.broadcastPresence(client.userID, true, nil)

		case client := <-h.unregister:
			h.mu.Lock()
			removed := false
			if current, ok := h.clients[client.userID]; ok && current == client {
				delete(h.clients, client.userID)
				close(client.send)
				removed = true
			}
			h.mu.Unlock()
			log.Printf("websocket: user %s disconnected", client.userID)
			// Only when this was a real removal (not a reconnect that replaced the
			// old connection): stamp last_seen and tell peers they went offline.
			if removed {
				go h.handleDisconnect(client.userID)
			}
		}
	}
}

// handleDisconnect records the user's last-seen time and broadcasts their offline
// transition. Runs off the hub goroutine so the DB write never blocks routing.
func (h *Hub) handleDisconnect(userID uuid.UUID) {
	now := time.Now()
	if h.postgres != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.postgres.UpdateLastSeen(ctx, userID, now); err != nil {
			log.Printf("websocket: update last_seen for %s failed: %v", userID, err)
		}
	}
	ms := now.UnixMilli()
	h.broadcastPresence(userID, false, &ms)
}

// broadcastPresence pushes an online/offline transition for userID to every
// connected client (best-effort — see Broadcast). lastSeen is set only for the
// offline transition.
func (h *Hub) broadcastPresence(userID uuid.UUID, online bool, lastSeen *int64) {
	payload, err := json.Marshal(presenceUpdateFrame{
		Type:     framePresenceUpdate,
		UserID:   userID.String(),
		IsOnline: online,
		LastSeen: lastSeen,
	})
	if err != nil {
		return
	}
	h.Broadcast(payload)
}

// Register adds a client to the hub's active connection pool.
func (h *Hub) Register(client *Client) {
	h.register <- client
}

// Unregister removes a client from the hub's active connection pool.
func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}

// DeliverToUser forwards an encrypted payload to the receiver's active WebSocket connection.
// Returns true when the receiver is online and the message was queued for delivery.
func (h *Hub) DeliverToUser(receiverID uuid.UUID, payload []byte) bool {
	h.mu.RLock()
	client, ok := h.clients[receiverID]
	h.mu.RUnlock()
	if !ok {
		log.Printf("websocket: route miss — receiver %s is not connected to this hub", receiverID)
		return false
	}

	select {
	case client.send <- payload:
		log.Printf("websocket: route hit — payload queued for receiver %s", receiverID)
		return true
	default:
		log.Printf("websocket: send buffer full for user %s", receiverID)
		return false
	}
}

// Broadcast queues a payload to every currently connected client, best-effort.
// Used for profile updates (user_update) that all peers should pick up live. A
// client whose send buffer is full has the frame dropped rather than blocking
// the hub — the update is non-critical and clients also refresh on next fetch.
func (h *Hub) Broadcast(payload []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, client := range h.clients {
		select {
		case client.send <- payload:
		default:
			log.Printf("websocket: broadcast drop — send buffer full for user %s", client.userID)
		}
	}
}

// IsOnline reports whether a user currently has an active WebSocket connection.
func (h *Hub) IsOnline(userID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.clients[userID]
	return ok
}
