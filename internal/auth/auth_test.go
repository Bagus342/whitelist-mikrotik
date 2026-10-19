package auth

import (
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3, 500*time.Millisecond, 2*time.Second)

	ip := "192.168.1.50"

	// 1. Initial state - not locked
	locked, _ := rl.CheckLimit(ip)
	if locked {
		t.Errorf("expected IP to not be locked initially")
	}

	// 2. Failure 1
	isLocked, _, failures := rl.RecordFailure(ip)
	if isLocked || failures != 1 {
		t.Errorf("expected failure 1 to not lock, got locked=%v, failures=%d", isLocked, failures)
	}

	// 3. Failure 2
	isLocked, _, failures = rl.RecordFailure(ip)
	if isLocked || failures != 2 {
		t.Errorf("expected failure 2 to not lock, got locked=%v, failures=%d", isLocked, failures)
	}

	// 4. Failure 3 (Threshold reached -> Lockout!)
	isLocked, remaining, failures := rl.RecordFailure(ip)
	if !isLocked || failures != 3 {
		t.Errorf("expected failure 3 to trigger lockout, got locked=%v, failures=%d", isLocked, failures)
	}
	if remaining <= 0 {
		t.Errorf("expected positive remaining lockout time, got %v", remaining)
	}

	// 5. CheckLimit during lockout
	locked, _ = rl.CheckLimit(ip)
	if !locked {
		t.Errorf("expected CheckLimit to report locked")
	}

	// 6. Wait for lockout expiry
	time.Sleep(550 * time.Millisecond)
	locked, _ = rl.CheckLimit(ip)
	if locked {
		t.Errorf("expected lockout to expire after duration")
	}

	// 7. Success clears records
	rl.RecordFailure(ip)
	rl.RecordSuccess(ip)
	locked, _ = rl.CheckLimit(ip)
	if locked {
		t.Errorf("expected record to be cleared after success")
	}
}

func TestSessionStore(t *testing.T) {
	ttl := 300 * time.Millisecond
	store := NewSessionStore(ttl)

	// 1. Create Session
	sess, err := store.CreateSession("admin", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if len(sess.ID) != 64 { // 32 bytes hex = 64 chars
		t.Errorf("expected 64 char hex session ID, got len=%d", len(sess.ID))
	}
	if len(sess.CSRFToken) != 64 {
		t.Errorf("expected 64 char hex CSRF token, got len=%d", len(sess.CSRFToken))
	}

	// 2. Get active session
	retrieved, err := store.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("unexpected error getting session: %v", err)
	}
	if retrieved.Username != "admin" {
		t.Errorf("expected username 'admin', got %s", retrieved.Username)
	}

	// 3. Session Revocation
	store.RevokeSession(sess.ID)
	_, err = store.GetSession(sess.ID)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound after revoke, got %v", err)
	}

	// 4. Session Expiration
	sess2, _ := store.CreateSession("user2", "127.0.0.1", "Agent")
	time.Sleep(350 * time.Millisecond)
	_, err = store.GetSession(sess2.ID)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestPasswordHashing_And_Verification(t *testing.T) {
	password := "RahasiaSangatKuat#2026!"

	// 1. Plain text comparison (constant time)
	if !VerifyPassword(password, password) {
		t.Errorf("expected matching plain password to verify")
	}
	if VerifyPassword("WrongPassword", password) {
		t.Errorf("expected wrong plain password to fail")
	}

	// 2. PBKDF2 hash creation & verification
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if len(hash) < 30 {
		t.Errorf("expected valid hash string, got: %s", hash)
	}

	// 3. Verify correct password with PBKDF2 hash
	if !VerifyPassword(password, hash) {
		t.Errorf("expected correct password to verify against PBKDF2 hash")
	}

	// 4. Verify wrong password with PBKDF2 hash
	if VerifyPassword("SalahPassword", hash) {
		t.Errorf("expected wrong password to fail against PBKDF2 hash")
	}

	// 5. Empty inputs
	if VerifyPassword("", hash) || VerifyPassword(password, "") {
		t.Errorf("expected empty inputs to return false")
	}
}

func TestCSRFVerification(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890"

	if !VerifyCSRF(token, token) {
		t.Errorf("expected matching CSRF tokens to verify")
	}
	if VerifyCSRF("wrong-token", token) {
		t.Errorf("expected mismatching CSRF tokens to fail")
	}
	if VerifyCSRF("", token) || VerifyCSRF(token, "") {
		t.Errorf("expected empty CSRF tokens to fail")
	}
}
