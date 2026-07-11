// Package pin derives and validates VibeNet's anti-spam chat PINs.
//
// A user's required PIN is one of two kinds (see models.User.ChatPinType):
//
//   - "rotating": a 6-digit code derived deterministically from the user's ID and
//     the current 5-minute time window. It needs no storage — the owner and any
//     caller both compute the same value from the clock — and changes every 5
//     minutes automatically across every server instance.
//   - "static": the 6-digit CustomPin the user has set.
//
// Rotating codes are an HMAC over (userID, window) keyed by a server secret, so
// they can't be predicted without that secret even though they're unstored.
package pin

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/google/uuid"
)

// WindowSeconds is the rotating-PIN lifetime: the code changes every 5 minutes.
const WindowSeconds = 300

// secret keys the HMAC used to derive rotating PINs. It prefers CHAT_PIN_SECRET,
// falls back to JWT_SECRET (already configured in every real deployment) and then a
// dev-only default — so production gets an unguessable secret without a new env var.
// If the default is ever used, rotating PINs become predictable; set CHAT_PIN_SECRET
// or JWT_SECRET in any non-local environment.
var secret = []byte(firstNonEmpty(
	utils.GetEnv("CHAT_PIN_SECRET", ""),
	utils.GetEnv("JWT_SECRET", ""),
	"vibenet-dev-chat-pin-secret",
))

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// window returns the index of the 5-minute window containing t.
func window(t time.Time) int64 {
	return t.Unix() / WindowSeconds
}

// codeForWindow computes the 6-digit code for a user in a specific window.
func codeForWindow(userID uuid.UUID, w int64) string {
	mac := hmac.New(sha256.New, secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(w))
	mac.Write(userID[:])
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint32(sum[:4]) % 1000000
	return fmt.Sprintf("%06d", n)
}

// Rotating returns the 6-digit rotating PIN for a user at time t.
func Rotating(userID uuid.UUID, t time.Time) string {
	return codeForWindow(userID, window(t))
}

// CurrentExpiry returns the instant the window containing t ends — i.e. when the
// rotating PIN next changes. Used to tell the owner how long their code stays valid.
func CurrentExpiry(t time.Time) time.Time {
	return time.Unix((window(t)+1)*WindowSeconds, 0)
}

// CurrentCode returns the PIN a user should share right now given their settings:
// the static CustomPin, or the current rotating code. The bool is false when the
// user selected "static" but hasn't set a CustomPin yet.
func CurrentCode(user *models.User, now time.Time) (string, bool) {
	if user.ChatPinType == models.ChatPinStatic {
		if user.CustomPin == nil || *user.CustomPin == "" {
			return "", false
		}
		return *user.CustomPin, true
	}
	return Rotating(user.UserID, now), true
}

// Valid reports whether provided satisfies user's chat-PIN requirement. When the
// requirement is disabled, any input (including empty) passes. For rotating PINs the
// immediately previous window is also accepted, so a code entered right at the
// 5-minute boundary — or under a small clock skew — doesn't spuriously fail.
func Valid(user *models.User, provided string) bool {
	if !user.ChatPinEnabled {
		return true
	}
	provided = strings.TrimSpace(provided)
	if provided == "" {
		return false
	}
	if user.ChatPinType == models.ChatPinStatic {
		return user.CustomPin != nil && constEq(provided, *user.CustomPin)
	}
	now := time.Now()
	w := window(now)
	return constEq(provided, codeForWindow(user.UserID, w)) ||
		constEq(provided, codeForWindow(user.UserID, w-1))
}

// constEq compares two strings in constant time to avoid leaking the correct PIN
// through response-timing differences.
func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
