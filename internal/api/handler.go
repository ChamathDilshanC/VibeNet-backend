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
	"github.com/ChamathDilshanC/VibeNet-backend/internal/pin"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/storage"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Broadcaster delivers pre-marshalled frames to connected WebSocket clients.
// The websocket Hub satisfies it; it is declared here as an interface so the
// api package can push live updates without importing websocket (which would
// be a cycle — websocket already imports api). Injected via SetBroadcaster.
type Broadcaster interface {
	// Broadcast queues a frame to every connected client, best-effort.
	Broadcast(payload []byte)
	// DeliverToUser queues a frame to one user's live connection, if any.
	DeliverToUser(receiverID uuid.UUID, payload []byte) bool
	// InvalidateGroup drops the hub's cached member list for a group so the
	// next group frame sees membership changes (e.g. an accepted invite).
	InvalidateGroup(groupID uuid.UUID)
}

// Handler groups REST dependencies for auth and user routes.
type Handler struct {
	postgres    *db.PostgresRepo
	dynamo      *db.DynamoRepo
	jwt         *auth.JWTManager
	googleOAuth *auth.GoogleOAuthConfig
	broadcaster Broadcaster
	// avatarDir is the filesystem directory uploaded avatars are written to; it is
	// served publicly at "/uploads/avatars/" (see cmd/api/main.go). The stored
	// avatar_url is the backend-relative path under that route, not an absolute
	// URL — the client prefixes its API origin, so the same value stays correct
	// across dev/prod without a PUBLIC_BASE_URL to keep in sync.
	avatarDir string
	// s3 signs presigned upload/download URLs for E2EE file attachments (see
	// upload.go). Nil when AWS_S3_* is unset — GetUploadURL/GetDownloadURL then
	// answer 503 rather than panicking, the same graceful-degradation the
	// Google OAuth fields already get when unconfigured.
	s3 *storage.PresignClient
}

// NewHandler constructs an API handler with the required persistence and auth services.
// s3Presign may be nil when file attachments aren't configured for this deployment.
func NewHandler(postgres *db.PostgresRepo, dynamo *db.DynamoRepo, jwtManager *auth.JWTManager, googleCfg auth.GoogleOAuthConfig, s3Presign *storage.PresignClient) *Handler {
	cfgCopy := googleCfg
	// UPLOAD_DIR is the root served at "/uploads"; avatars live in its "avatars"
	// subdirectory.
	uploadDir := utils.GetEnv("UPLOAD_DIR", "./public/uploads")
	return &Handler{
		postgres:    postgres,
		dynamo:      dynamo,
		jwt:         jwtManager,
		googleOAuth: &cfgCopy,
		avatarDir:   filepath.Join(uploadDir, "avatars"),
		s3:          s3Presign,
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
	UserID         string  `json:"user_id"`
	Username       string  `json:"username"`
	DisplayName    string  `json:"display_name"`
	Email          *string `json:"email,omitempty"`
	PhoneNumber    *string `json:"phone_number,omitempty"`
	PublicKey      *string `json:"public_key,omitempty"`
	AvatarURL      *string `json:"avatar_url,omitempty"`
	ChatPinEnabled bool    `json:"chat_pin_enabled"`
	ChatPinType    string  `json:"chat_pin_type"`
	// Status is the account lifecycle state — "active", "deactivated", or "deleted".
	Status string `json:"status"`
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
	// LastSeen is unix milliseconds of the peer's last disconnect, so the client
	// can show "last seen ..." when they're offline. Omitted if never recorded.
	LastSeen *int64 `json:"last_seen,omitempty"`
	// Status is the target account's lifecycle state — "active", "deactivated", or
	// "deleted" — so a client with an existing conversation can reflect it (badge,
	// disabled composer) without a separate lookup.
	Status string `json:"status"`
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

// pinSettingsRequest is the body of PUT /api/user/settings/pin. CustomPin is only
// read when Type is "static"; it may be omitted to keep an existing custom PIN.
type pinSettingsRequest struct {
	Enabled   bool    `json:"enabled"`
	Type      string  `json:"type"`
	CustomPin *string `json:"custom_pin,omitempty"`
}

// pinVerifyRequest is the body of POST /api/user/verify-pin — the current user's own
// PIN, entered to unlock their chat interface.
type pinVerifyRequest struct {
	PIN string `json:"pin"`
}

// pinStatusResponse describes the owner's current chat-PIN state and the code they
// should share right now. PIN is empty when protection is disabled, or when "static"
// is selected but no custom PIN has been set. ExpiresAt is set only for rotating
// codes (when the current 5-minute window ends).
type pinStatusResponse struct {
	Enabled   bool       `json:"enabled"`
	Type      string     `json:"type"`
	PIN       string     `json:"pin"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// userSearchResult exposes only discovery-safe fields — the actual PIN is never returned.
type userSearchResult struct {
	UserID         string  `json:"user_id"`
	Username       string  `json:"username"`
	DisplayName    string  `json:"display_name"`
	ChatPinEnabled bool    `json:"chat_pin_enabled"`
	AvatarURL      *string `json:"avatar_url,omitempty"`
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
			r.Post("/user/deactivate", h.DeactivateAccount)
			r.Delete("/user/delete", h.DeleteAccount)
			r.Put("/user/profile", h.UpdateProfile)
			r.Post("/user/avatar", h.UploadAvatar)
			r.Get("/upload/presigned-url", h.GetUploadURL)
			r.Get("/upload/download-url", h.GetDownloadURL)
			r.Put("/user/public-key", h.UpdatePublicKey)
			r.Put("/user/settings/pin", h.UpdatePinSettings)
			r.Post("/user/verify-pin", h.VerifyPin)
			r.Get("/user/my-pin", h.GetMyChatPIN)
			r.Get("/users/search", h.SearchUsers)
			r.Get("/users/{id}/key", h.GetUserPublicKey)
			r.Post("/users/{id}/verify-pin", h.VerifyPeerPin)
			r.Get("/messages/{chatRoomID}", h.GetChatHistory)
			r.Get("/conversations/discover", h.GetDiscoverableConversations)
			r.Post("/groups/create", h.CreateGroup)
			r.Get("/groups", h.ListGroups)
			r.Put("/groups/{id}", h.UpdateGroup)
			r.Post("/groups/{id}/avatar", h.UploadGroupAvatar)
			r.Post("/groups/{id}/members", h.AddGroupMember)
			r.Put("/groups/{id}/members/{user_id}/role", h.UpdateMemberRole)
			r.Delete("/groups/{id}/members/{user_id}", h.RemoveGroupMember)
			r.Post("/groups/{id}/leave", h.LeaveGroup)
			r.Get("/invites", h.ListInvites)
			r.Post("/invites/accept", h.AcceptInvite)
			r.Post("/invites/decline", h.DeclineInvite)
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

	// Checked after the password so an attacker without valid credentials learns
	// nothing about an account's lifecycle state.
	if msg, blocked := loginBlockedReason(user.Status); blocked {
		writeError(w, http.StatusForbidden, msg)
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

// loginBlockedReason reports whether an account status should prevent a new JWT
// from being issued, and if so, the message to surface. Shared by Login and
// GoogleCallback so both authentication paths enforce the same lifecycle rule.
func loginBlockedReason(status string) (message string, blocked bool) {
	switch status {
	case models.UserStatusDeactivated:
		return "This account has been deactivated.", true
	case models.UserStatusDeleted:
		return "This account no longer exists.", true
	default:
		return "", false
	}
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

// DeactivateAccount flips the authenticated account to "deactivated": it can no
// longer sign in (see loginBlockedReason and the WebSocket handshake), but every
// column — profile, messages, PIN settings — is left intact, so peers keep seeing
// the account's name/avatar (the client shows a "Deactivated" badge) and it can be
// brought back by a future reactivation path. Reversible, unlike DeleteAccount.
//
// The client that just called this clears its own session and redirects to /login;
// the JWT already issued for this device stays cryptographically valid until it
// expires (VibeNet issues stateless bearer tokens with no server-side revocation —
// see JWTManager), but every future login attempt — from this device or any other —
// is rejected from this point on.
func (h *Handler) DeactivateAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.postgres.DeactivateUser(r.Context(), userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to deactivate account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "account deactivated"})
}

// DeleteAccount permanently disables the authenticated account: status becomes
// "deleted" and every PII column (real name, email, phone number, avatar, password
// hash, Google linkage, chat PIN) is wiped — see PostgresRepo.DeleteUser. UserID is
// never removed, so messages already stored in DynamoDB keep a valid sender_id; the
// client resolves that id to "Deleted User" once it sees this account's status.
// Unlike DeactivateAccount, there is no way back from this endpoint.
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.postgres.DeleteUser(r.Context(), userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "account deleted"})
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

// storeUploadedAvatar validates and persists a multipart image upload (the
// "avatar" field) under a random UUID filename in the avatars directory. It
// writes the error response itself on failure (ok=false); on success it
// returns the public backend-relative URL and the on-disk path so the caller
// can clean up if its own DB write fails. Shared by the user-profile and
// group-photo upload endpoints.
func (h *Handler) storeUploadedAvatar(w http.ResponseWriter, r *http.Request) (avatarURL, dstPath string, ok bool) {
	// Cap the request body before parsing so an oversized upload is rejected
	// without buffering it all into memory or disk.
	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes)
	if err := r.ParseMultipartForm(maxAvatarBytes); err != nil {
		writeError(w, http.StatusBadRequest, "image is too large (max 5 MB) or the upload was malformed")
		return "", "", false
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		writeError(w, http.StatusBadRequest, "no image file provided under the \"avatar\" field")
		return "", "", false
	}
	defer file.Close()

	// Sniff the real content type from the first bytes rather than trusting the
	// client's declared type or filename, then map it to an allowed extension.
	head := make([]byte, 512)
	n, _ := io.ReadFull(file, head)
	contentType := http.DetectContentType(head[:n])
	ext, allowed := allowedAvatarTypes[contentType]
	if !allowed {
		writeError(w, http.StatusBadRequest, "unsupported image type; use JPEG, PNG, WebP, or GIF")
		return "", "", false
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read image")
		return "", "", false
	}

	if err := os.MkdirAll(h.avatarDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return "", "", false
	}
	// The filename is a fresh UUID plus the vetted extension — no user input reaches
	// the path, so there is nothing to traverse out of the avatars directory.
	filename := uuid.NewString() + ext
	dstPath = filepath.Join(h.avatarDir, filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return "", "", false
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		os.Remove(dstPath)
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return "", "", false
	}
	if err := dst.Close(); err != nil {
		os.Remove(dstPath)
		writeError(w, http.StatusInternalServerError, "failed to store image")
		return "", "", false
	}

	// Return a backend-relative path; the client prefixes its API origin when it
	// loads the image. This keeps the value portable across environments.
	return "/uploads/avatars/" + filename, dstPath, true
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

	avatarURL, dstPath, ok := h.storeUploadedAvatar(w, r)
	if !ok {
		return
	}

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

// sixDigitPattern matches a 6-digit static chat PIN.
var sixDigitPattern = regexp.MustCompile(`^[0-9]{6}$`)

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

// GetUserPublicKey returns a user's E2EE public key for message encryption on the
// client. The chat PIN is single-sided (the current user unlocks the interface with
// their own PIN via VerifyPin), so fetching a peer's key is not PIN-gated here.
func (h *Handler) GetUserPublicKey(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	userID, err := uuid.Parse(idParam)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	publicKey, avatarURL, displayName, lastSeen, status, err := h.postgres.GetPublicKey(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "public key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch public key")
		return
	}

	var lastSeenMS *int64
	if lastSeen != nil {
		ms := lastSeen.UnixMilli()
		lastSeenMS = &ms
	}

	// A deleted account's display_name/avatar_url are already wiped (see DeleteUser),
	// but display_name falls back to the still-intact username — override it here so
	// a deleted account's former handle is never surfaced to a peer.
	if status == models.UserStatusDeleted {
		displayName = "Deleted User"
		avatarURL = nil
	}

	writeJSON(w, http.StatusOK, publicKeyResponse{
		UserID:      userID.String(),
		DisplayName: displayName,
		PublicKey:   publicKey,
		AvatarURL:   avatarURL,
		LastSeen:    lastSeenMS,
		Status:      status,
	})
}

// VerifyPin checks a PIN the authenticated user entered to unlock their own chat
// interface against their own active PIN (static custom PIN or current rotating
// code). Returns 200 {"valid":true} on success, 403 on a wrong PIN. When the user
// has the PIN disabled there is nothing to check, so it succeeds.
func (h *Handler) VerifyPin(w http.ResponseWriter, r *http.Request) {
	var req pinVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

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
		writeError(w, http.StatusInternalServerError, "failed to verify pin")
		return
	}

	if !pin.Valid(user, strings.TrimSpace(req.PIN)) {
		writeError(w, http.StatusForbidden, "incorrect PIN")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

// VerifyPeerPin checks a PIN the authenticated caller entered against a TARGET
// user's active chat-PIN profile — the anti-spam gate a recipient sets so only
// people they've shared their code with can start a conversation with them (see
// package pin). Distinct from VerifyPin, which validates the caller's OWN PIN.
// Returns 200 {"valid":true} on success, 403 on a wrong PIN. When the target has
// the PIN disabled there is nothing to check, so it succeeds. The target's actual
// PIN is never returned. Requires authentication so anonymous callers can't probe
// arbitrary users' PINs.
func (h *Handler) VerifyPeerPin(w http.ResponseWriter, r *http.Request) {
	if _, ok := UserIDFromContext(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req pinVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	target, err := h.postgres.GetUserByID(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to verify pin")
		return
	}

	if !pin.Valid(target, strings.TrimSpace(req.PIN)) {
		writeError(w, http.StatusForbidden, "incorrect PIN")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

// UpdatePinSettings persists the authenticated user's chat-PIN configuration:
// whether it's enabled, the type ("rotating" or "static"), and — for the static
// type — a 6-digit custom PIN. Expects JSON {"enabled":bool,"type":string,"custom_pin":string?}.
// Responds with the resulting pinStatusResponse (the same shape as GET /user/my-pin).
func (h *Handler) UpdatePinSettings(w http.ResponseWriter, r *http.Request) {
	var req pinSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	req.Type = strings.TrimSpace(req.Type)
	if req.Type != models.ChatPinRotating && req.Type != models.ChatPinStatic {
		writeError(w, http.StatusBadRequest, `type must be "rotating" or "static"`)
		return
	}

	// For the static type, a supplied custom PIN must be exactly 6 digits. It may be
	// omitted to keep a previously-set PIN, but never left unset on first use.
	var customPin *string
	if req.Type == models.ChatPinStatic && req.CustomPin != nil {
		trimmed := strings.TrimSpace(*req.CustomPin)
		if !sixDigitPattern.MatchString(trimmed) {
			writeError(w, http.StatusBadRequest, "custom PIN must be exactly 6 digits")
			return
		}
		customPin = &trimmed
	}

	user, err := h.postgres.UpdatePinSettings(r.Context(), userID, req.Enabled, req.Type, customPin)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrInvalidPinType):
			writeError(w, http.StatusBadRequest, `type must be "rotating" or "static"`)
		case errors.Is(err, gorm.ErrRecordNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		default:
			writeError(w, http.StatusInternalServerError, "failed to update pin settings")
		}
		return
	}

	// Guard against selecting static with no PIN ever set.
	if user.ChatPinEnabled && user.ChatPinType == models.ChatPinStatic &&
		(user.CustomPin == nil || *user.CustomPin == "") {
		writeError(w, http.StatusBadRequest, "set a 6-digit custom PIN to use a static code")
		return
	}

	writeJSON(w, http.StatusOK, pinStatusFor(user))
}

// GetMyChatPIN returns the authenticated user's current chat-PIN status and the code
// they should share right now — the static custom PIN, or the active rotating code.
func (h *Handler) GetMyChatPIN(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusInternalServerError, "failed to fetch pin")
		return
	}

	writeJSON(w, http.StatusOK, pinStatusFor(user))
}

// pinStatusFor projects a user's PIN settings into the API response, computing the
// shareable code (and its expiry, for rotating codes) via internal/pin.
func pinStatusFor(user *models.User) pinStatusResponse {
	resp := pinStatusResponse{
		Enabled: user.ChatPinEnabled,
		Type:    user.ChatPinType,
	}
	if !user.ChatPinEnabled {
		return resp
	}
	now := time.Now()
	if code, ok := pin.CurrentCode(user, now); ok {
		resp.PIN = code
		if user.ChatPinType == models.ChatPinRotating {
			expiry := pin.CurrentExpiry(now)
			resp.ExpiresAt = &expiry
		}
	}
	return resp
}

// SearchUsers finds users by username prefix for chat discovery. It returns the user ID,
// username, and chat_pin_enabled flag only — the actual PIN is never exposed.
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
			UserID:         users[i].UserID.String(),
			Username:       users[i].Username,
			DisplayName:    displayNameOfUser(&users[i]),
			ChatPinEnabled: users[i].ChatPinEnabled,
			AvatarURL:      users[i].AvatarURL,
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

	// Two room shapes exist: "group:<group_id>" (membership checked in Postgres)
	// and the direct-message "<user_id>:<user_id>" pair (the caller must be one
	// of the two IDs).
	if groupIDRaw, isGroup := strings.CutPrefix(chatRoomID, "group:"); isGroup {
		groupID, err := uuid.Parse(groupIDRaw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid chat room id")
			return
		}
		isMember, err := h.postgres.IsGroupMember(r.Context(), groupID, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify group membership")
			return
		}
		if !isMember {
			writeError(w, http.StatusForbidden, "not a participant of this chat room")
			return
		}
	} else {
		parts := strings.Split(chatRoomID, ":")
		if len(parts) != 2 || (parts[0] != userID.String() && parts[1] != userID.String()) {
			writeError(w, http.StatusForbidden, "not a participant of this chat room")
			return
		}
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

// discoverableConversationDTO is one row returned by GetDiscoverableConversations —
// enough of the peer's profile for the client to materialize a full local
// conversation (see conversations.ts) without a second round trip per peer.
type discoverableConversationDTO struct {
	ChatRoomID  string  `json:"chat_room_id"`
	PeerID      string  `json:"peer_id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
	PublicKey   *string `json:"public_key,omitempty"`
	Status      string  `json:"status"`
}

// GetDiscoverableConversations lists every direct-message room the caller is a
// participant in per the server-side index (see PostgresRepo.RecordDMParticipants),
// so a client can surface a first-contact conversation someone else opened while
// this device was offline. The WebSocket hub only delivers live and there is
// otherwise no server-side "conversations" list at all — a DM is normally just
// two user IDs and a client-side cache (see conversations.ts on the frontend).
// The client is expected to diff this against its local cache and only
// materialize entries it doesn't already have.
func (h *Handler) GetDiscoverableConversations(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := h.postgres.ListDiscoverableDMs(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list conversations")
		return
	}

	dtos := make([]discoverableConversationDTO, 0, len(rows))
	for _, row := range rows {
		dtos = append(dtos, discoverableConversationDTO{
			ChatRoomID:  row.ChatRoomID,
			PeerID:      row.PeerID.String(),
			Username:    row.Username,
			DisplayName: row.DisplayName,
			AvatarURL:   row.AvatarURL,
			PublicKey:   row.PublicKey,
			Status:      row.Status,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"conversations": dtos})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}
