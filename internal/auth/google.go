package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GoogleUserInfo represents the profile payload returned by Google's userinfo endpoint.
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// FetchGoogleUserInfo retrieves the authenticated Google account profile using an OAuth2 access token.
func FetchGoogleUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("build google userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch google userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google userinfo status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var info GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode google userinfo: %w", err)
	}
	if info.ID == "" || info.Email == "" {
		return nil, fmt.Errorf("google userinfo missing required fields")
	}
	return &info, nil
}

// DeriveUsername builds a unique-friendly username from a Google display name or email local-part.
func DeriveUsername(displayName, email string) string {
	candidate := strings.TrimSpace(displayName)
	if candidate == "" {
		parts := strings.Split(email, "@")
		candidate = parts[0]
	}

	candidate = strings.ToLower(candidate)
	candidate = strings.ReplaceAll(candidate, " ", "_")
	candidate = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' {
			return r
		}
		return -1
	}, candidate)

	if candidate == "" {
		candidate = "google_user"
	}
	if len(candidate) > 48 {
		candidate = candidate[:48]
	}
	return candidate
}
