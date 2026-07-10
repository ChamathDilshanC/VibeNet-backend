// Package websocket implements real-time encrypted message routing for VibeNet.
// The hub acts as a blind router: it forwards ciphertext only and never inspects message content.
package websocket

import (
	"log"
	"sync"

	"github.com/google/uuid"
)

// Hub maintains active WebSocket connections and routes encrypted payloads between clients.
type Hub struct {
	clients    map[uuid.UUID]*Client
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// NewHub creates and starts a Hub event loop in a background goroutine.
func NewHub() *Hub {
	hub := &Hub{
		clients:    make(map[uuid.UUID]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
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

		case client := <-h.unregister:
			h.mu.Lock()
			if current, ok := h.clients[client.userID]; ok && current == client {
				delete(h.clients, client.userID)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("websocket: user %s disconnected", client.userID)
		}
	}
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

// IsOnline reports whether a user currently has an active WebSocket connection.
func (h *Hub) IsOnline(userID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.clients[userID]
	return ok
}
