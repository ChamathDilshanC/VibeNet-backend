package pin

import (
	"testing"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/google/uuid"
)

func TestRotatingIsDeterministicAndSixDigits(t *testing.T) {
	id := uuid.New()
	base := time.Unix(1_700_000_000, 0)

	a := Rotating(id, base)
	b := Rotating(id, base.Add(30*time.Second)) // same 5-minute window
	if a != b {
		t.Fatalf("expected same code within a window, got %q and %q", a, b)
	}
	if len(a) != 6 {
		t.Fatalf("expected 6-digit code, got %q", a)
	}
	for _, r := range a {
		if r < '0' || r > '9' {
			t.Fatalf("expected all digits, got %q", a)
		}
	}

	// A different window generally yields a different code.
	if next := Rotating(id, base.Add(WindowSeconds*time.Second)); next == a {
		t.Errorf("expected code to change across windows, both were %q", a)
	}

	// Different users get different codes in the same window.
	if other := Rotating(uuid.New(), base); other == a {
		t.Errorf("expected per-user codes to differ")
	}
}

func TestValid(t *testing.T) {
	id := uuid.New()
	now := time.Now()
	current := Rotating(id, now)
	previous := Rotating(id, now.Add(-WindowSeconds*time.Second))

	rotating := &models.User{UserID: id, ChatPinEnabled: true, ChatPinType: models.ChatPinRotating}
	if !Valid(rotating, current) {
		t.Error("current rotating code should be valid")
	}
	if !Valid(rotating, previous) {
		t.Error("previous-window code should be accepted for grace")
	}
	if Valid(rotating, "000000") && current != "000000" && previous != "000000" {
		t.Error("an arbitrary wrong code should be rejected")
	}
	if Valid(rotating, "") {
		t.Error("empty code should be rejected when enabled")
	}

	custom := "246810"
	static := &models.User{ChatPinEnabled: true, ChatPinType: models.ChatPinStatic, CustomPin: &custom}
	if !Valid(static, custom) {
		t.Error("matching custom PIN should be valid")
	}
	if Valid(static, "111111") {
		t.Error("non-matching custom PIN should be rejected")
	}

	disabled := &models.User{ChatPinEnabled: false}
	if !Valid(disabled, "") {
		t.Error("disabled PIN should accept any input")
	}
}
