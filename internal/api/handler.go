// Package api exposes VibeNet REST endpoints for authentication and user management.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/auth"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Handler groups REST dependencies for auth and user routes.
type Handler struct {
	postgres    *db.PostgresRepo
	dynamo      *db.DynamoRepo
	jwt         *auth.JWTManager
	googleOAuth *auth.GoogleOAuthConfig
}

// NewHandler constructs an API handler with the required persistence and auth services.
func NewHandler(postgres *db.PostgresRepo, dynamo *db.DynamoRepo, jwtManager *auth.JWTManager, googleCfg auth.GoogleOAuthConfig) *Handler {
	cfgCopy := googleCfg
	return &Handler{
		postgres:    postgres,
		dynamo:      dynamo,
		jwt:         jwtManager,
		googleOAuth: &cfgCopy,
	}
}

type registerRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type publicKeyRequest struct {
	PublicKey string `json:"public_key"`
}

type authResponse struct {
	Token string      `json:"token"`
	User  userSummary `json:"user"`
}

type userSummary struct {
	UserID    string  `json:"user_id"`
	Username  string  `json:"username"`
	Email     *string `json:"email,omitempty"`
	PublicKey *string `json:"public_key,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty"`
}

type profileUpdateRequest struct {
	Username string `json:"username"`
}

type publicKeyResponse struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
}

type pinToggleRequest struct {
	RequirePIN bool `json:"require_pin"`
}

type pinToggleResponse struct {
	RequirePIN bool `json:"require_pin"`
}

type chatPINResponse struct {
	PIN       string    `json:"pin"`
	ExpiresAt time.Time `json:"expires_at"`
}

// userSearchResult exposes only discovery-safe fields — the actual PIN is never returned.
type userSearchResult struct {
	UserID     string `json:"user_id"`
	Username   string `json:"username"`
	RequirePIN bool   `json:"require_pin"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// RegisterRoutes mounts authentication and user management endpoints on the provided router.
func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Route("/api", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", h.Register)
			r.Post("/login", h.Login)
			r.Get("/google/login", h.GoogleLogin)
			r.Get("/google/callback", h.GoogleCallback)
		})

		r.Group(func(r chi.Router) {
			r.Use(h.JWTAuthMiddleware)
			r.Get("/user/me", h.GetMe)
			r.Put("/user/profile", h.UpdateProfile)
			r.Put("/user/public-key", h.UpdatePublicKey)
			r.Put("/user/settings/pin-toggle", h.ToggleChatPIN)
			r.Get("/user/my-pin", h.GetMyChatPIN)
			r.Get("/users/search", h.SearchUsers)
			r.Get("/users/{id}/key", h.GetUserPublicKey)
			r.Get("/messages/{chatRoomID}", h.GetChatHistory)
		})
	})
}

// Register creates a standard VibeNet account with a password and E2EE public key.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.Username == "" || req.Password == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "username, password, and public_key are required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user, err := h.postgres.CreateUser(r.Context(), req.Username, string(hash), req.PublicKey, nil)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "username already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	token, err := h.jwt.GenerateToken(user.UserID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusCreated, authResponse{
		Token: token,
		User:  toUserSummary(user),
	})
}

// Login authenticates a standard user and returns a signed JWT.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := h.postgres.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to lookup user")
		return
	}

	if user.PasswordHash == nil {
		writeError(w, http.StatusUnauthorized, "this account uses Google sign-in")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := h.jwt.GenerateToken(user.UserID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		Token: token,
		User:  toUserSummary(user),
	})
}

// GetMe returns the authenticated user's current profile. The JWT only carries
// user_id and username, so this is how a client learns fields that can change
// after the token was issued — notably the Google avatar_url.
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.postgres.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	writeJSON(w, http.StatusOK, toUserSummary(user))
}

// UpdateProfile renames the authenticated user. The username doubles as the
// display name across the client, so this is the profile edit surface.
//
// The issued JWT still carries the old username in its claims; nothing on the
// server reads that claim (authorization is by user_id), and the token stays
// valid until it expires.
func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	var req profileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if err := validateUsername(req.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.postgres.UpdateProfile(r.Context(), userID, req.Username)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrUsernameTaken):
			writeError(w, http.StatusConflict, "username already taken")
		case errors.Is(err, gorm.ErrRecordNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		default:
			writeError(w, http.StatusInternalServerError, "failed to update profile")
		}
		return
	}

	writeJSON(w, http.StatusOK, toUserSummary(user))
}

// usernamePattern is a superset of the character set auth.DeriveUsername
// produces for Google accounts (which is lowercase-only), so a provisioned name
// always survives a round trip through the profile editor while still letting a
// user pick a mixed-case display name like "ChamathDilshanC". Uniqueness is
// enforced case-insensitively in the repository, so casing is cosmetic only.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._]+$`)

func validateUsername(username string) error {
	switch {
	case len(username) < 3:
		return errors.New("username must be at least 3 characters")
	case len(username) > 48:
		return errors.New("username must be at most 48 characters")
	case !usernamePattern.MatchString(username):
		return errors.New("username may only contain letters, numbers, dots, and underscores")
	}
	return nil
}

// UpdatePublicKey stores or updates the authenticated user's E2EE public key.
func (h *Handler) UpdatePublicKey(w http.ResponseWriter, r *http.Request) {
	var req publicKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}

	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.postgres.UpdatePublicKey(r.Context(), userID, req.PublicKey); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update public key")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "public key updated"})
}

// GetUserPublicKey returns a user's E2EE public key for message encryption on the client.
//
// If the target user has enabled the anti-spam rotating PIN, the caller must present the
// current PIN via the optional `?pin=xxxx` query parameter. A missing, wrong, or expired
// PIN results in 403 Forbidden.
func (h *Handler) GetUserPublicKey(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	userID, err := uuid.Parse(idParam)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	providedPIN := strings.TrimSpace(r.URL.Query().Get("pin"))

	publicKey, err := h.postgres.GetPublicKey(r.Context(), userID, providedPIN)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrChatPINRequired):
			writeError(w, http.StatusForbidden, "invalid or expired PIN")
			return
		case errors.Is(err, gorm.ErrRecordNotFound):
			writeError(w, http.StatusNotFound, "public key not found")
			return
		default:
			writeError(w, http.StatusInternalServerError, "failed to fetch public key")
			return
		}
	}

	writeJSON(w, http.StatusOK, publicKeyResponse{
		UserID:    userID.String(),
		PublicKey: publicKey,
	})
}

// ToggleChatPIN enables or disables the authenticated user's anti-spam chat PIN requirement.
// Expects JSON body {"require_pin": true|false}.
func (h *Handler) ToggleChatPIN(w http.ResponseWriter, r *http.Request) {
	var req pinToggleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.postgres.ToggleChatPIN(r.Context(), userID, req.RequirePIN); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update pin setting")
		return
	}

	writeJSON(w, http.StatusOK, pinToggleResponse{RequirePIN: req.RequirePIN})
}

// GetMyChatPIN returns the authenticated user's currently active 4-digit PIN, generating a
// fresh one when none exists or the previous PIN has expired.
func (h *Handler) GetMyChatPIN(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	pin, expiry, err := h.postgres.GetOrRefreshChatPIN(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch pin")
		return
	}

	writeJSON(w, http.StatusOK, chatPINResponse{PIN: pin, ExpiresAt: expiry})
}

// SearchUsers finds users by username prefix for chat discovery. It returns the user ID,
// username, and require_pin flag only — the actual PIN is never exposed.
func (h *Handler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("username"))
	if query == "" {
		writeError(w, http.StatusBadRequest, "username query parameter is required")
		return
	}

	users, err := h.postgres.SearchUsersByUsername(r.Context(), query, 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to search users")
		return
	}

	results := make([]userSearchResult, 0, len(users))
	for i := range users {
		results = append(results, userSearchResult{
			UserID:     users[i].UserID.String(),
			Username:   users[i].Username,
			RequirePIN: users[i].RequireChatPIN,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"results": results})
}

// chatMessageDTO exposes a stored message's ciphertext and routing metadata only —
// the backend never has, and never returns, plaintext.
type chatMessageDTO struct {
	MessageID  string `json:"message_id"`
	SenderID   string `json:"sender_id"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// GetChatHistory returns cached encrypted messages for a chat room, letting a client
// catch up on messages sent while it was offline (the WebSocket hub only delivers to
// currently-connected clients and does not queue). Access is restricted to the two
// participants encoded in the room id — see chatRoomIdFor on the frontend, which
// derives it as the two user IDs sorted and joined with ":".
func (h *Handler) GetChatHistory(w http.ResponseWriter, r *http.Request) {
	// chi.URLParam returns the raw, still-percent-encoded path segment (e.g. a
	// client-side encodeURIComponent turns the ":" separator into "%3A") — it
	// does not decode it the way r.URL.Path does. Unescape explicitly rather
	// than relying on the caller not to encode it.
	chatRoomID, err := url.PathUnescape(chi.URLParam(r, "chatRoomID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid chat room id")
		return
	}

	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	parts := strings.Split(chatRoomID, ":")
	if len(parts) != 2 || (parts[0] != userID.String() && parts[1] != userID.String()) {
		writeError(w, http.StatusForbidden, "not a participant of this chat room")
		return
	}

	limit := int32(50)
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = int32(parsed)
		}
	}

	messages, err := h.dynamo.GetMessages(r.Context(), chatRoomID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch message history")
		return
	}

	dtos := make([]chatMessageDTO, 0, len(messages))
	for i := range messages {
		dtos = append(dtos, chatMessageDTO{
			MessageID:  messages[i].MessageID,
			SenderID:   messages[i].SenderID,
			Ciphertext: messages[i].Ciphertext,
			Nonce:      messages[i].Nonce,
			Timestamp:  messages[i].Timestamp,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"messages": dtos})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}
