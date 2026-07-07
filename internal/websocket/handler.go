package websocket

import (
	"log"
	"net/http"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/api"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Handler upgrades HTTP connections to WebSocket after JWT authentication.
type Handler struct {
	hub        *Hub
	apiHandler *api.Handler
	dynamo     *db.DynamoRepo
}

// NewHandler constructs a WebSocket handler with hub routing and persistence dependencies.
func NewHandler(hub *Hub, apiHandler *api.Handler, dynamo *db.DynamoRepo) *Handler {
	return &Handler{
		hub:        hub,
		apiHandler: apiHandler,
		dynamo:     dynamo,
	}
}

// ServeHTTP upgrades the connection to WebSocket when a valid JWT is provided.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}
	}
	if token == "" {
		http.Error(w, "missing authentication token", http.StatusUnauthorized)
		return
	}

	claims, err := h.apiHandler.ValidateToken(token)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Error(w, "invalid token subject", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}

	NewClient(h.hub, conn, userID, h.dynamo)
}
