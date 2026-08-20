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

// groupMembersTTL bounds how long a group's member list is served from the
// in-process cache. Group frames (messages, typing) can fan out several times a
// second, so hitting Postgres per frame would be wasteful — but membership must
// converge quickly after a join. REST-side joins call InvalidateGroup for an
// instant refresh; the TTL is the backstop for anything that slips through.
const groupMembersTTL = 30 * time.Second

// groupMembersEntry is one cached group roster with its expiry.
type groupMembersEntry struct {
	memberIDs []uuid.UUID
	expiresAt time.Time
}

// Hub maintains active WebSocket connections and routes encrypted payloads between clients.
type Hub struct {
	clients    map[uuid.UUID]*Client
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	// postgres stamps last_seen when a user disconnects and resolves group
	// membership for room fan-out. Optional (nil in tests): presence broadcasts
	// still fire and group routing degrades to a no-op.
	postgres *db.PostgresRepo
	// groupMembers caches group rosters for room broadcasts (see groupMembersTTL).
	groupMembers   map[uuid.UUID]groupMembersEntry
	groupMembersMu sync.Mutex
}

// NewHub creates and starts a Hub event loop in a background goroutine. postgres
// may be nil (e.g. in tests) to skip last-seen persistence.
func NewHub(postgres *db.PostgresRepo) *Hub {
	hub := &Hub{
		clients:      make(map[uuid.UUID]*Client),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		postgres:     postgres,
		groupMembers: make(map[uuid.UUID]groupMembersEntry),
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

// GroupMemberIDs resolves a group's member list for room routing, serving from
// the short-TTL cache when fresh. Returns nil (not an error) when the hub has
// no Postgres handle (tests) — group routing is then a no-op.
func (h *Hub) GroupMemberIDs(groupID uuid.UUID) ([]uuid.UUID, error) {
	if h.postgres == nil {
		return nil, nil
	}

	h.groupMembersMu.Lock()
	entry, ok := h.groupMembers[groupID]
	h.groupMembersMu.Unlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.memberIDs, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	memberIDs, err := h.postgres.GetGroupMemberIDs(ctx, groupID)
	if err != nil {
		return nil, err
	}

	h.groupMembersMu.Lock()
	h.groupMembers[groupID] = groupMembersEntry{
		memberIDs: memberIDs,
		expiresAt: time.Now().Add(groupMembersTTL),
	}
	h.groupMembersMu.Unlock()
	return memberIDs, nil
}

// InvalidateGroup drops a group's cached member list so the next frame re-reads
// membership from Postgres. Called by the REST layer when someone joins.
func (h *Hub) InvalidateGroup(groupID uuid.UUID) {
	h.groupMembersMu.Lock()
	delete(h.groupMembers, groupID)
	h.groupMembersMu.Unlock()
}

// RecordDMParticipants indexes a direct-message room's two participants in
// Postgres so each side's client can later discover the room even if it
// wasn't connected when the other side sent the opening message — see
// PostgresRepo.ListDiscoverableDMs and GetDiscoverableConversations. Meant to
// be called from a goroutine (like the caller's message save): best-effort
// and non-blocking, since a failure here only degrades that catch-up path,
// not delivery of the message itself. No-op when the hub has no Postgres
// handle (tests).
func (h *Hub) RecordDMParticipants(chatRoomID string, userA, userB uuid.UUID) {
	if h.postgres == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.postgres.RecordDMParticipants(ctx, chatRoomID, userA, userB); err != nil {
		log.Printf("websocket: failed to index dm participants for room %s: %v", chatRoomID, err)
	}
}

// IsGroupMemberCached reports whether userID is in the group's (possibly
// cached) member list — the authorization check for inbound group frames.
func (h *Hub) IsGroupMemberCached(groupID, userID uuid.UUID) bool {
	memberIDs, err := h.GroupMemberIDs(groupID)
	if err != nil {
		log.Printf("websocket: group membership lookup failed for %s: %v", groupID, err)
		return false
	}
	for _, id := range memberIDs {
		if id == userID {
			return true
		}
	}
	return false
}

// DeliverToGroup queues an encrypted payload to every member of the group that
// currently has a live connection, skipping the sender (whose client already
// rendered the message optimistically). Returns how many members it reached —
// zero both when everyone is offline and when the membership lookup failed.
func (h *Hub) DeliverToGroup(groupID, senderID uuid.UUID, payload []byte) int {
	memberIDs, err := h.GroupMemberIDs(groupID)
	if err != nil {
		log.Printf("websocket: group fan-out aborted, membership lookup failed for %s: %v", groupID, err)
		return 0
	}

	// Route directly rather than via DeliverToUser: an offline member is the
	// normal case in a group, not a "route miss" worth a log line each.
	h.mu.RLock()
	defer h.mu.RUnlock()
	delivered := 0
	for _, memberID := range memberIDs {
		if memberID == senderID {
			continue
		}
		client, ok := h.clients[memberID]
		if !ok {
			continue
		}
		select {
		case client.send <- payload:
			delivered++
		default:
			log.Printf("websocket: group send buffer full for user %s", memberID)
		}
	}
	return delivered
}
