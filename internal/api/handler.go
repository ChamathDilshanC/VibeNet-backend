// Package api exposes VibeNet REST endpoints for authentication and user management.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/auth"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Broadcaster delivers a pre-marshalled frame to every connected WebSocket
// client. The websocket Hub satisfies it; it is declared here as an interface so
// the api package can push live updates without importing websocket (which would
// be a cycle — websocket already imports api). Injected via SetBroadcaster.
type Broadcaster interface {
	Broadcast(payload []byte)
}

// Handler groups REST dependencies for auth and user routes.
type Handler struct {
	postgres    *db.PostgresRepo
	dynamo      *db.DynamoRepo
	jwt         *auth.JWTManager
	googleOAuth *auth.GoogleOAuthConfig
	broadcaster Broadcaster
	// avatarDir is the filesystem directory uploaded avatars are written to; it is
	// served publicly at "/uploads/avatars/" (see cmd/api/main.go). publicBaseURL is
	// the origin prepended to the stored path so avatar_url is absolute — the client
	// loads it directly from the backend, just like the Google-hosted photos.
	avatarDir     string
	publicBaseURL string
}

// NewHandler constructs an API handler with the required persistence and auth services.
func NewHandler(postgres *db.PostgresRepo, dynamo *db.DynamoRepo, jwtManager *auth.JWTManager, googleCfg auth.GoogleOAuthConfig) *Handler {
	cfgCopy := googleCfg
	// UPLOAD_DIR is the root served at "/uploads"; avatars live in its "avatars"
	// subdirectory. PUBLIC_BASE_URL is where the backend is reachable from browsers.
	uploadDir := utils.GetEnv("UPLOAD_DIR", "./public/uploads")
	return &Handler{
		postgres:      postgres,
		dynamo:        dynamo,
		jwt:           jwtManager,
		googleOAuth:   &cfgCopy,
		avatarDir:     filepath.Join(uploadDir, "avatars"),
		publicBaseURL: strings.TrimRight(utils.GetEnv("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
	}
}

// SetBroadcaster wires in the WebSocket hub after construction, breaking the
// otherwise-circular dependency between the api and websocket packages. Safe to
// leave unset (e.g. in tests): broadcasts are then skipped.
func (h *Handler) SetBroadcaster(b Broadcaster) {
	h.broadcaster = b
}

type registerRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	PublicKey   string `json:"public_key"`
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
	UserID      string  `json:"user_id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	Email       *string `json:"email,omitempty"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	PublicKey   *string `json:"public_key,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

type profileUpdateRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type publicKeyResponse struct {
	UserID      string  `json:"user_id"`
	DisplayName string  `json:"display_name"`
	PublicKey   string  `json:"public_key"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

// userUpdateBroadcast is pushed to every connected client when a user edits
// their profile, so peers update the name/avatar they show mid-chat without a
// reload. It carries no ciphertext — purely public profile fields.
type userUpdateBroadcast struct {
	Type        string  `json:"type"`
	UserID      string  `json:"user_id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
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
	UserID      string  `json:"user_id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	RequirePIN  bool    `json:"require_pin"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
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
			r.Post("/user/avatar", h.UploadAvatar)
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
	req.Email = strings.TrimSpace(req.Email)
	// Normalize the phone number to digits (and an optional leading "+") so the
	// same number typed with different separators maps to one stored value.
	req.PhoneNumber = phoneSeparators.ReplaceAllString(strings.TrimSpace(req.PhoneNumber), "")
	if req.Username == "" || req.Password == "" || req.PublicKey == "" || req.Email == "" || req.PhoneNumber == "" {
		writeError(w, http.StatusBadRequest, "username, password, email, phone_number, and public_key are required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if err := validateEmail(req.Email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validatePhoneNumber(req.PhoneNumber); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	email := req.Email
	phone := req.PhoneNumber
	user, err := h.postgres.CreateUser(r.Context(), req.Username, string(hash), req.PublicKey, &email, &phone)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrEmailTaken):
			writeError(w, http.StatusConflict, "email already registered")
		case errors.Is(err, db.ErrPhoneTaken):
			writeError(w, http.StatusConflict, "phone number already registered")
		case strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique"):
			writeError(w, http.StatusConflict, "username already exists")
		default:
			writeError(w, http.StatusInternalServerError, "failed to create user")
		}
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

// UpdateProfile edits the authenticated user's login username and display name
// (the "real name" shown throughout the client). Username uniqueness is enforced
// case-insensitively; the display name has no such constraint. A blank display
// name falls back to the username so the account always has a usable label.
//
// On success it broadcasts a user_update frame to every connected client so
// peers refresh the name/avatar they show without a reload.
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

	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if err := validateDisplayName(req.DisplayName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// An omitted/blank real name defaults to the username rather than storing an
	// empty label — mirrors the seed behaviour at sign-up.
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}

	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.postgres.UpdateProfile(r.Context(), userID, req.Username, req.DisplayName)
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

	summary := toUserSummary(user)
	h.broadcastUserUpdate(summary)
	writeJSON(w, http.StatusOK, summary)
}

// broadcastUserUpdate pushes the updated public profile to all connected clients.
// Best-effort and non-blocking (see Hub.Broadcast); a nil broadcaster (unset in
// tests) or a marshal error simply skips the notification.
func (h *Handler) broadcastUserUpdate(summary userSummary) {
	if h.broadcaster == nil {
		return
	}
	payload, err := json.Marshal(userUpdateBroadcast{
		Type:        "user_update",
		UserID:      summary.UserID,
		Username:    summary.Username,
		DisplayName: summary.DisplayName,
		AvatarURL:   summary.AvatarURL,
	})
	if err != nil {
		return
	}
	h.broadcaster.Broadcast(payload)
}

// maxAvatarBytes caps an uploaded avatar. Profile pictures are small; the limit
// keeps a hostile client from filling the disk or holding the request open.
const maxAvatarBytes = 5 << 20 // 5 MiB

// allowedAvatarTypes maps the content type sniffed from the file's bytes to the
// extension we store it under. The extension is derived here, never taken from
// the client-supplied filename, so a crafted name cannot inject a path or a
// misleading type.
var allowedAvatarTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

// UploadAvatar accepts a multipart/form-data image under the "avatar" field,
// stores it under a random UUID filename in the avatars directory, points the
// user's avatar_url at the public URL, and broadcasts the change so every peer's
// chat UI refreshes the picture live. It returns the updated profile summary.
func (h *Handler) UploadAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Cap the request body before parsing so an oversized upload is rejected
	// without buffering it all into memory or disk.
	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes)
	if err := r.ParseMultipartForm(maxAvatarBytes); err != nil {
		writeError(w, http.StatusBadRequest, "image is too large (max 5 MB) or the upload was malformed")
		return
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		writeError(w, http.StatusBadRequest, "no image file provided under the \"avatar\" field")
		return
	}
	defer file.Close()

	// Sniff the real content type from the first bytes rather than trusting the
	// client's declared type or filename, then map it to an allowed extension.
	head := make([]byte, 512)
	n, _ := io.ReadFull(file, head)
	contentType := http.DetectContentType(head[:n])
	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported image type; use JPEG, PNG, WebP, or GIF")
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read image")
		return
	}

	if err := os.MkdirAll(h.avatarDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return
	}
	// The filename is a fresh UUID plus the vetted extension — no user input reaches
	// the path, so there is nothing to traverse out of the avatars directory.
	filename := uuid.NewString() + ext
	dstPath := filepath.Join(h.avatarDir, filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		os.Remove(dstPath)
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return
	}
	if err := dst.Close(); err != nil {
		os.Remove(dstPath)
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return
	}

	avatarURL := h.publicBaseURL + "/uploads/avatars/" + filename
	user, err := h.postgres.UpdateAvatarURL(r.Context(), userID, avatarURL)
	if err != nil {
		// Don't leave an orphaned file behind if the DB write fails.
		os.Remove(dstPath)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update profile picture")
		return
	}

	summary := toUserSummary(user)
	h.broadcastUserUpdate(summary)
	writeJSON(w, http.StatusOK, summary)
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

// emailPattern is a deliberately permissive check — enough to reject obvious
// typos (missing "@" or domain) without trying to fully model RFC 5322. Real
// deliverability isn't verified since VibeNet doesn't send email at sign-up.
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func validateEmail(email string) error {
	switch {
	case len(email) > 255:
		return errors.New("email must be at most 255 characters")
	case !emailPattern.MatchString(email):
		return errors.New("please enter a valid email address")
	}
	return nil
}

// phonePattern accepts an optional leading "+" followed by 7–15 digits, matching
// the E.164 range. Separators (spaces, dashes, parentheses) are stripped by the
// caller before validation, so only digits and the "+" reach here.
var phonePattern = regexp.MustCompile(`^\+?[0-9]{7,15}$`)

func validatePhoneNumber(phone string) error {
	if !phonePattern.MatchString(phone) {
		return errors.New("please enter a valid phone number")
	}
	return nil
}

// phoneSeparators matches the human-friendly grouping characters people type into
// a phone field; they are removed before storage so the same number entered as
// "+1 (555) 010-1234" or "+15550101234" collides in the unique index.
var phoneSeparators = regexp.MustCompile(`[\s().-]`)

// validateDisplayName bounds the free-form "real name". Unlike the username it
// allows spaces and mixed case (it is a human name, not a handle) but is capped
// to the column width. An empty value is accepted here and defaulted by the
// caller to the username.
func validateDisplayName(displayName string) error {
	if len(displayName) > 64 {
		return errors.New("real name must be at most 64 characters")
	}
	return nil
}

// displayNameOfUser returns a user's display name, falling back to the username
// when none is set (rows predating the column). Keeps every name a client sees
// non-empty, matching toUserSummary's fallback.
func displayNameOfUser(user *models.User) string {
	if strings.TrimSpace(user.DisplayName) != "" {
		return user.DisplayName
	}
	return user.Username
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

	publicKey, avatarURL, displayName, err := h.postgres.GetPublicKey(r.Context(), userID, providedPIN)
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
		UserID:      userID.String(),
		DisplayName: displayName,
		PublicKey:   publicKey,
		AvatarURL:   avatarURL,
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
			UserID:      users[i].UserID.String(),
			Username:    users[i].Username,
			DisplayName: displayNameOfUser(&users[i]),
			RequirePIN:  users[i].RequireChatPIN,
			AvatarURL:   users[i].AvatarURL,
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
