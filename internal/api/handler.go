// Package api exposes VibeNet REST endpoints for authentication and user management.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
	jwt         *auth.JWTManager
	googleOAuth *auth.GoogleOAuthConfig
}

// NewHandler constructs an API handler with the required persistence and auth services.
func NewHandler(postgres *db.PostgresRepo, jwtManager *auth.JWTManager, googleCfg auth.GoogleOAuthConfig) *Handler {
	cfgCopy := googleCfg
	return &Handler{
		postgres:    postgres,
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
}

type publicKeyResponse struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
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
			r.Put("/user/public-key", h.UpdatePublicKey)
			r.Get("/users/{id}/key", h.GetUserPublicKey)
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
func (h *Handler) GetUserPublicKey(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	userID, err := uuid.Parse(idParam)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	publicKey, err := h.postgres.GetPublicKey(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "public key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch public key")
		return
	}

	writeJSON(w, http.StatusOK, publicKeyResponse{
		UserID:    userID.String(),
		PublicKey: publicKey,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}
