// Package auth provides JWT token management and Google OAuth configuration for VibeNet.
package auth

import (
	"fmt"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Claims represents the JWT payload issued after successful authentication.
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// JWTManager signs and validates bearer tokens for REST and WebSocket authentication.
type JWTManager struct {
	secret []byte
	ttl    time.Duration
}

// GoogleOAuthConfig holds Google OAuth2 client credentials loaded from the environment.
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	// RedirectURL is Google's callback into this backend (the Authorized redirect URI).
	RedirectURL string
	// FrontendURL is the base origin of the SPA. After a successful Google sign-in the
	// backend redirects the browser to <FrontendURL>/auth/google-success?token=... so the
	// front-end can capture the issued JWT and store the session.
	FrontendURL string
}

// LoadGoogleOAuthConfig builds GoogleOAuthConfig from environment variables.
func LoadGoogleOAuthConfig() GoogleOAuthConfig {
	return GoogleOAuthConfig{
		ClientID:     utils.GetEnv("GOOGLE_CLIENT_ID", ""),
		ClientSecret: utils.GetEnv("GOOGLE_CLIENT_SECRET", ""),
		RedirectURL:  utils.GetEnv("GOOGLE_REDIRECT_URL", ""),
		FrontendURL:  utils.GetEnv("FRONTEND_URL", "http://localhost:3000"),
	}
}

// NewJWTManager creates a JWTManager using the configured secret and token lifetime.
func NewJWTManager() *JWTManager {
	ttlHours := utils.GetEnv("JWT_EXPIRY_HOURS", "72")
	hours := 72
	if _, err := fmt.Sscanf(ttlHours, "%d", &hours); err != nil || hours <= 0 {
		hours = 72
	}

	return &JWTManager{
		secret: []byte(utils.GetEnv("JWT_SECRET", "change-me-in-production")),
		ttl:    time.Duration(hours) * time.Hour,
	}
}

// GenerateToken issues a signed JWT for the authenticated user.
func (m *JWTManager) GenerateToken(userID uuid.UUID, username string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID.String(),
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// ValidateToken parses and verifies a bearer token, returning the embedded claims.
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid jwt claims")
	}
	return claims, nil
}

// BuildGoogleOAuth2Config constructs the OAuth2 config for Google sign-in.
func BuildGoogleOAuth2Config(cfg GoogleOAuthConfig) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}
