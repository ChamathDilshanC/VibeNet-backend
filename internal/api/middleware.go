package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/auth"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/google/uuid"
)

type contextKey string

const userIDContextKey contextKey = "userID"
const usernameContextKey contextKey = "username"

// JWTAuthMiddleware validates bearer tokens and injects the authenticated user into the request context.
func (h *Handler) JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		claims, err := h.jwt.ValidateToken(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token subject")
			return
		}

		ctx := context.WithValue(r.Context(), userIDContextKey, userID)
		ctx = context.WithValue(ctx, usernameContextKey, claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserIDFromContext extracts the authenticated user's ID from the request context.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	return userID, ok
}

// UsernameFromContext extracts the authenticated user's username from the request context.
func UsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameContextKey).(string)
	return username, ok
}

// extractBearerToken reads a JWT from the Authorization header or token query parameter.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

func toUserSummary(user *models.User) userSummary {
	displayName := user.DisplayName
	if strings.TrimSpace(displayName) == "" {
		// Rows created before display_name existed carry an empty value; fall back
		// to the username so the client always has a name to render.
		displayName = user.Username
	}
	return userSummary{
		UserID:      user.UserID.String(),
		Username:    user.Username,
		DisplayName: displayName,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		PublicKey:   user.PublicKey,
		AvatarURL:   user.AvatarURL,
	}
}

// ValidateToken exposes JWT validation for WebSocket upgrade authentication.
func (h *Handler) ValidateToken(token string) (*auth.Claims, error) {
	return h.jwt.ValidateToken(token)
}
