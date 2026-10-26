package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionNotFound = errors.New("session not found")
	ErrInvalidCSRF     = errors.New("invalid or missing CSRF token")
)

// ============================================================================
// 1. CRYPTOGRAPHIC SESSION MANAGEMENT
// ============================================================================

// Session represents an authenticated user session.
type Session struct {
	ID        string
	Username  string
	ClientIP  string
	UserAgent string
	CSRFToken string
	// IDToken is the raw OIDC id_token, kept as id_token_hint for SSO logout.
	IDToken   string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SessionStore provides thread-safe in-memory session management.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewSessionStore creates a new session store.
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}

	store := &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}

	// Auto-cleanup expired sessions every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			store.cleanup()
		}
	}()

	return store
}

// CreateSession generates a new cryptographically secure session ID and CSRF token
// for a user authenticated via Authentik. idToken is kept for SSO logout.
func (s *SessionStore) CreateSession(username, clientIP, userAgent, idToken string) (*Session, error) {
	// 256-bit (32 bytes) cryptographically random session ID
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random session ID: %w", err)
	}
	sessionID := hex.EncodeToString(b)

	// 256-bit CSRF token
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random CSRF token: %w", err)
	}
	csrfToken := hex.EncodeToString(csrfBytes)

	now := time.Now()
	sess := &Session{
		ID:        sessionID,
		Username:  username,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		CSRFToken: csrfToken,
		IDToken:   idToken,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = sess

	return sess, nil
}

// GetSession retrieves and validates an active session. Refreshes sliding expiration.
func (s *SessionStore) GetSession(sessionID string) (*Session, error) {
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	now := time.Now()
	if sess.ExpiresAt.Before(now) {
		delete(s.sessions, sessionID)
		return nil, ErrSessionExpired
	}

	// Sliding expiration renewal on active usage
	sess.ExpiresAt = now.Add(s.ttl)
	return sess, nil
}

// RevokeSession invalidates and removes a session immediately.
func (s *SessionStore) RevokeSession(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *SessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, sess := range s.sessions {
		if sess.ExpiresAt.Before(now) {
			delete(s.sessions, id)
		}
	}
}

// VerifyCSRF checks the request CSRF token against the session CSRF token.
func VerifyCSRF(requestToken, sessionToken string) bool {
	reqB := []byte(strings.TrimSpace(requestToken))
	sessB := []byte(strings.TrimSpace(sessionToken))
	if len(reqB) == 0 || len(sessB) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(reqB, sessB) == 1
}
