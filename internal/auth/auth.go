package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
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
	ErrRateLimited     = errors.New("too many failed login attempts, please try again later")
	ErrInvalidCSRF     = errors.New("invalid or missing CSRF token")
)

// ============================================================================
// 1. RATE LIMITER & BRUTE FORCE PROTECTION
// ============================================================================

type LoginAttempt struct {
	Failures    int
	LockedUntil time.Time
	LastAttempt time.Time
}

// RateLimiter tracks failed login attempts by client IP and temporarily
// locks out IPs that exceed the failure threshold.
type RateLimiter struct {
	mu          sync.Mutex
	attempts    map[string]*LoginAttempt
	maxFailures int
	lockoutTime time.Duration
	windowTime  time.Duration
}

// NewRateLimiter initializes a new brute force rate limiter.
// Default: 5 failures within 5 minutes results in a 15-minute lockout.
func NewRateLimiter(maxFailures int, lockoutTime, windowTime time.Duration) *RateLimiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockoutTime <= 0 {
		lockoutTime = 15 * time.Minute
	}
	if windowTime <= 0 {
		windowTime = 5 * time.Minute
	}

	rl := &RateLimiter{
		attempts:    make(map[string]*LoginAttempt),
		maxFailures: maxFailures,
		lockoutTime: lockoutTime,
		windowTime:  windowTime,
	}

	// Periodic cleanup of stale attempt records every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

// CheckLimit checks if an IP is currently locked out.
// Returns (isLocked, remainingDuration).
func (rl *RateLimiter) CheckLimit(ip string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	attempt, exists := rl.attempts[ip]
	if !exists {
		return false, 0
	}

	now := time.Now()
	if attempt.LockedUntil.After(now) {
		return true, attempt.LockedUntil.Sub(now)
	}

	// If lockout expired or window expired, reset
	if now.Sub(attempt.LastAttempt) > rl.windowTime {
		delete(rl.attempts, ip)
	}

	return false, 0
}

// RecordFailure records a failed login attempt for the given IP.
// Returns (isNowLocked, remainingDuration, currentFailures).
func (rl *RateLimiter) RecordFailure(ip string) (bool, time.Duration, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	attempt, exists := rl.attempts[ip]
	if !exists || now.Sub(attempt.LastAttempt) > rl.windowTime {
		attempt = &LoginAttempt{LastAttempt: now}
		rl.attempts[ip] = attempt
	}

	attempt.Failures++
	attempt.LastAttempt = now

	if attempt.Failures >= rl.maxFailures {
		attempt.LockedUntil = now.Add(rl.lockoutTime)
		return true, rl.lockoutTime, attempt.Failures
	}

	return false, 0, attempt.Failures
}

// RecordSuccess clears any failure records for the given IP upon successful authentication.
func (rl *RateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, attempt := range rl.attempts {
		if attempt.LockedUntil.Before(now) && now.Sub(attempt.LastAttempt) > rl.windowTime {
			delete(rl.attempts, ip)
		}
	}
}

// ============================================================================
// 2. CRYPTOGRAPHIC SESSION MANAGEMENT
// ============================================================================

// Session represents an authenticated user session.
type Session struct {
	ID        string
	Username  string
	ClientIP  string
	UserAgent string
	CSRFToken string
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

// CreateSession generates a new cryptographically secure session ID and CSRF token.
func (s *SessionStore) CreateSession(username, clientIP, userAgent string) (*Session, error) {
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

// ============================================================================
// 3. SECURE PASSWORD HASHING & TIMING-ATTACK RESISTANCE (PBKDF2-HMAC-SHA256)
// ============================================================================

// HashPassword creates a secure PBKDF2-HMAC-SHA256 hash with a cryptographically random 16-byte salt.
// Format: pbkdf2$sha256$100000$<salt_hex>$<hash_hex>
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}

	iterations := 100000
	derived := pbkdf2([]byte(password), salt, iterations, 32)

	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s", iterations, hex.EncodeToString(salt), hex.EncodeToString(derived)), nil
}

// VerifyPassword checks a password against a plain password or PBKDF2 hash using constant-time comparison.
func VerifyPassword(inputPassword, expectedPasswordOrHash string) bool {
	inputPassword = strings.TrimSpace(inputPassword)
	expectedPasswordOrHash = strings.TrimSpace(expectedPasswordOrHash)

	if inputPassword == "" || expectedPasswordOrHash == "" {
		// Run dummy work to maintain constant timing
		_ = pbkdf2([]byte("dummy"), []byte("1234567890123456"), 1000, 32)
		return false
	}

	// Check if expected is a PBKDF2 hash
	if strings.HasPrefix(expectedPasswordOrHash, "pbkdf2$sha256$") {
		parts := strings.Split(expectedPasswordOrHash, "$")
		if len(parts) != 5 {
			return false
		}

		iterations := 100000
		salt, err := hex.DecodeString(parts[3])
		if err != nil {
			return false
		}
		expectedDerived, err := hex.DecodeString(parts[4])
		if err != nil {
			return false
		}

		actualDerived := pbkdf2([]byte(inputPassword), salt, iterations, len(expectedDerived))
		return subtle.ConstantTimeCompare(actualDerived, expectedDerived) == 1
	}

	// Standard plain comparison using constant-time equality
	return subtle.ConstantTimeCompare([]byte(inputPassword), []byte(expectedPasswordOrHash)) == 1
}

// pbkdf2 implements RFC 2898 Key Derivation Function 2 using HMAC-SHA256.
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var result []byte
	block := make([]byte, len(salt)+4)
	copy(block, salt)

	for i := 1; i <= numBlocks; i++ {
		binary.BigEndian.PutUint32(block[len(salt):], uint32(i))
		prf.Reset()
		_, _ = prf.Write(block)
		u := prf.Sum(nil)
		uXOR := make([]byte, len(u))
		copy(uXOR, u)

		for j := 2; j <= iterations; j++ {
			prf.Reset()
			_, _ = prf.Write(u)
			u = prf.Sum(nil)
			for k := 0; k < len(u); k++ {
				uXOR[k] ^= u[k]
			}
		}

		result = append(result, uXOR...)
	}

	return result[:keyLen]
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
