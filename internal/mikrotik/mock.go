package mikrotik

import (
	"context"
	"sync"
	"time"
)

// MockClient is an in-memory implementation of Client for unit testing.
type MockClient struct {
	mu          sync.Mutex
	WhitelistFn func(ctx context.Context, ip string) (*WhitelistResult, error)
	RemoveFn    func(ctx context.Context, ip string) error
	PingFn      func(ctx context.Context) error
	CloseFn     func() error

	// In-memory store for simulating behavior if custom functions are not provided.
	// Entries represents the whitelist address list (key: IP).
	Entries map[string]MockEntry

	// AbuseEntries represents the "port-forward-abuse" address list (key: IP).
	AbuseEntries map[string]MockEntry
}

// MockEntry represents an address-list entry in MockClient.
type MockEntry struct {
	ID        string
	List      string
	Address   string
	Comment   string
	Timeout   string
	ExpiresAt time.Time
}

// NewMockClient initializes a new MockClient.
func NewMockClient() *MockClient {
	return &MockClient{
		Entries:      make(map[string]MockEntry),
		AbuseEntries: make(map[string]MockEntry),
	}
}

// AddAbuseEntry adds an IP entry to the simulated port-forward-abuse address list.
func (m *MockClient) AddAbuseEntry(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AbuseEntries[ip] = MockEntry{
		ID:      "*abuse-" + ip,
		List:    "port-forward-abuse",
		Address: ip,
		Comment: "manual-review",
	}
}

// Whitelist simulates adding or extending an address-list entry.
// If the IP exists in AbuseEntries ("port-forward-abuse"), it removes it first.
func (m *MockClient) Whitelist(ctx context.Context, ip string) (*WhitelistResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.WhitelistFn != nil {
		return m.WhitelistFn(ctx, ip)
	}

	// 1. If present in abuse list, remove it first
	removedFromAbuse := false
	if _, exists := m.AbuseEntries[ip]; exists {
		delete(m.AbuseEntries, ip)
		removedFromAbuse = true
	}

	expiresAt := time.Now().Add(8 * time.Hour)
	entry, exists := m.Entries[ip]
	if exists {
		entry.Timeout = "8h"
		entry.ExpiresAt = expiresAt
		m.Entries[ip] = entry
		return &WhitelistResult{
			Action:           ActionExtended,
			IP:               ip,
			ExpiresAt:        expiresAt,
			RemovedFromAbuse: removedFromAbuse,
		}, nil
	}

	m.Entries[ip] = MockEntry{
		ID:        "*1",
		List:      "remote-whitelist",
		Address:   ip,
		Comment:   "wl|" + time.Now().Format(time.RFC3339),
		Timeout:   "8h",
		ExpiresAt: expiresAt,
	}

	return &WhitelistResult{
		Action:           ActionAdded,
		IP:               ip,
		ExpiresAt:        expiresAt,
		RemovedFromAbuse: removedFromAbuse,
	}, nil
}

// Remove simulates removing an address-list entry.
func (m *MockClient) Remove(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.RemoveFn != nil {
		return m.RemoveFn(ctx, ip)
	}

	entry, exists := m.Entries[ip]
	if !exists {
		return ErrNotFound
	}

	if len(entry.Comment) < 3 || entry.Comment[:3] != "wl|" {
		return ErrNotManaged
	}

	delete(m.Entries, ip)
	return nil
}

// Ping simulates checking RouterOS health.
func (m *MockClient) Ping(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.PingFn != nil {
		return m.PingFn(ctx)
	}
	return nil
}

// Close simulates closing the client connection.
func (m *MockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}
