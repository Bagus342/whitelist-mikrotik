package auth

import (
	"testing"
	"time"
)

func TestSessionStore(t *testing.T) {
	ttl := 300 * time.Millisecond
	store := NewSessionStore(ttl)

	// 1. Create Session
	sess, err := store.CreateSession("admin", "127.0.0.1", "TestAgent", "")
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
	sess2, _ := store.CreateSession("user2", "127.0.0.1", "Agent", "")
	time.Sleep(350 * time.Millisecond)
	_, err = store.GetSession(sess2.ID)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
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
