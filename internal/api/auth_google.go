package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/auth"
	"golang.org/x/oauth2"
)

const oauthStateCookie = "vibenet_oauth_state"

// GoogleLogin redirects the client to Google's OAuth consent screen.
func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	if h.googleOAuth.ClientID == "" || h.googleOAuth.ClientSecret == "" || h.googleOAuth.RedirectURL == "" {
		writeError(w, http.StatusServiceUnavailable, "google oauth is not configured")
		return
	}

	state, err := generateOAuthState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate oauth state")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	oauthCfg := auth.BuildGoogleOAuth2Config(*h.googleOAuth)
	url := oauthCfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GoogleCallback exchanges the authorization code, provisions the user if needed, and returns a JWT.
func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	if h.googleOAuth.ClientID == "" || h.googleOAuth.ClientSecret == "" || h.googleOAuth.RedirectURL == "" {
		writeError(w, http.StatusServiceUnavailable, "google oauth is not configured")
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, "missing oauth state or code")
		return
	}

	cookie, err := r.Cookie(oauthStateCookie)
	if err != nil || cookie.Value == "" || cookie.Value != state {
		writeError(w, http.StatusBadRequest, "invalid oauth state")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	oauthCfg := auth.BuildGoogleOAuth2Config(*h.googleOAuth)
	token, err := oauthCfg.Exchange(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to exchange oauth code")
		return
	}

	profile, err := auth.FetchGoogleUserInfo(r.Context(), token.AccessToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch google profile")
		return
	}

	username := auth.DeriveUsername(profile.Name, profile.Email)
	user, err := h.postgres.CreateOrGetUserByGoogle(r.Context(), profile.ID, profile.Email, username)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			username = fmt.Sprintf("%s_%s", username, profile.ID[:8])
			user, err = h.postgres.CreateOrGetUserByGoogle(r.Context(), profile.ID, profile.Email, username)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to provision google user")
			return
		}
	}

	jwtToken, err := h.jwt.GenerateToken(user.UserID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		Token: jwtToken,
		User:  toUserSummary(user),
	})
}

// generateOAuthState creates a cryptographically secure CSRF token for the OAuth flow.
func generateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

