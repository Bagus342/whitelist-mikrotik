package mikrotik

import (
	"context"
	"strings"
	"sync"
	"time"
)

// MockClient is an in-memory implementation of Client for unit testing.
type MockClient struct {
	mu             sync.Mutex
	WhitelistFn    func(ctx context.Context, ip string, hostname ...string) (*WhitelistResult, error)
	RemoveFn       func(ctx context.Context, ip string) error
	AllowWinboxFn  func(ctx context.Context, ip string) error
	RemoveWinboxFn func(ctx context.Context, ip string) error
	GetStatusFn    func(ctx context.Context, ip string) (*StatusResult, error)
	ListEntriesFn  func(ctx context.Context) ([]EntryResult, error)
	PingFn         func(ctx context.Context) error
	CloseFn        func() error

	// In-memory store for simulating behavior if custom functions are not provided.
	// Entries represents the whitelist address list (key: IP).
	Entries map[string]MockEntry

	// AbuseEntries represents the "port-forward-abuse" address list (key: IP).
	AbuseEntries map[string]MockEntry

	// WinboxAddresses stores the allowed addresses for the simulated winbox service.
	WinboxAddresses []string
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
		Entries:         make(map[string]MockEntry),
		AbuseEntries:    make(map[string]MockEntry),
		WinboxAddresses: make([]string, 0),
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
func (m *MockClient) Whitelist(ctx context.Context, ip string, hostname ...string) (*WhitelistResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.WhitelistFn != nil {
		return m.WhitelistFn(ctx, ip, hostname...)
	}

	// 1. If present in abuse list, remove it first
	removedFromAbuse := false
	if _, exists := m.AbuseEntries[ip]; exists {
		delete(m.AbuseEntries, ip)
		removedFromAbuse = true
	}

	targetHost := ip
	if len(hostname) > 0 && strings.TrimSpace(hostname[0]) != "" {
		targetHost = SanitizeHostname(hostname[0])
	}
	if targetHost == "" {
		targetHost = ip
	}
	comment := "wl|" + targetHost

	expiresAt := time.Now().Add(8 * time.Hour)
	entry, exists := m.Entries[ip]
	if exists {
		entry.Timeout = "8h"
		entry.ExpiresAt = expiresAt
		if strings.HasPrefix(entry.Comment, "wl|") {
			entry.Comment = comment
		}
		m.Entries[ip] = entry
		return &WhitelistResult{
			Action:           ActionExtended,
			IP:               ip,
			Hostname:         targetHost,
			ExpiresAt:        expiresAt,
			RemovedFromAbuse: removedFromAbuse,
		}, nil
	}

	m.Entries[ip] = MockEntry{
		ID:        "*1",
		List:      "remote-whitelist",
		Address:   ip,
		Comment:   comment,
		Timeout:   "8h",
		ExpiresAt: expiresAt,
	}

	return &WhitelistResult{
		Action:           ActionAdded,
		IP:               ip,
		Hostname:         targetHost,
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

// AllowWinbox simulates adding the target IP (as /32 or /128) to the allowed Winbox addresses.
func (m *MockClient) AllowWinbox(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.AllowWinboxFn != nil {
		return m.AllowWinboxFn(ctx, ip)
	}

	cidr := FormatWinboxCIDR(ip)
	for _, addr := range m.WinboxAddresses {
		if addr == cidr || addr == ip || strings.TrimSuffix(addr, "/32") == ip || strings.TrimSuffix(addr, "/128") == ip {
			return nil
		}
	}

	m.WinboxAddresses = append(m.WinboxAddresses, cidr)
	return nil
}

// RemoveWinbox simulates removing the target IP from the allowed Winbox addresses.
func (m *MockClient) RemoveWinbox(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.RemoveWinboxFn != nil {
		return m.RemoveWinboxFn(ctx, ip)
	}

	cidr := FormatWinboxCIDR(ip)
	var filtered []string
	for _, addr := range m.WinboxAddresses {
		if addr == cidr || addr == ip || strings.TrimSuffix(addr, "/32") == ip || strings.TrimSuffix(addr, "/128") == ip {
			continue
		}
		filtered = append(filtered, addr)
	}
	m.WinboxAddresses = filtered
	return nil
}

// HasWinboxAddress checks whether an IP or CIDR is present in the mock Winbox addresses.
func (m *MockClient) HasWinboxAddress(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.hasWinboxAddressLocked(ip)
}

func (m *MockClient) hasWinboxAddressLocked(ip string) bool {
	cidr := FormatWinboxCIDR(ip)
	for _, addr := range m.WinboxAddresses {
		if addr == cidr || addr == ip || strings.TrimSuffix(addr, "/32") == ip || strings.TrimSuffix(addr, "/128") == ip {
			return true
		}
	}
	return false
}

// GetStatus simulates querying whitelist status, abuse status, and winbox status for a given IP.
func (m *MockClient) GetStatus(ctx context.Context, ip string) (*StatusResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.GetStatusFn != nil {
		return m.GetStatusFn(ctx, ip)
	}

	entry, isWhitelisted := m.Entries[ip]
	comment := ""
	timeout := ""
	hostname := ip
	var expiresAt time.Time
	if isWhitelisted {
		comment = entry.Comment
		timeout = entry.Timeout
		expiresAt = entry.ExpiresAt
		if strings.HasPrefix(comment, "wl|") {
			hostname = strings.TrimPrefix(comment, "wl|")
		}
	}

	_, inAbuse := m.AbuseEntries[ip]
	isWinboxAllowed := m.hasWinboxAddressLocked(ip)

	var allEntries []EntryResult
	for _, e := range m.Entries {
		isManaged := strings.HasPrefix(e.Comment, "wl|")
		h := e.Comment
		if isManaged {
			h = strings.TrimPrefix(e.Comment, "wl|")
		}
		allEntries = append(allEntries, EntryResult{
			ID:            e.ID,
			Address:       e.Address,
			List:          e.List,
			Comment:       e.Comment,
			Hostname:      h,
			Timeout:       e.Timeout,
			IsManaged:     isManaged,
			WinboxAllowed: m.hasWinboxAddressLocked(e.Address),
		})
	}

	return &StatusResult{
		ClientIP:         ip,
		Hostname:         hostname,
		ISP:              DetectISP(ctx, ip),
		IsWhitelisted:    isWhitelisted,
		Comment:          comment,
		Timeout:          timeout,
		ExpiresAt:        expiresAt,
		IsInAbuseList:    inAbuse,
		IsWinboxAllowed:  isWinboxAllowed,
		TotalWhitelisted: len(m.Entries),
		WhitelistTTL:     "8h",
		MikrotikAddress:  "192.168.48.1:8728",
		Entries:          allEntries,
	}, nil
}

// ListEntries simulates listing all whitelist entries.
func (m *MockClient) ListEntries(ctx context.Context) ([]EntryResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ListEntriesFn != nil {
		return m.ListEntriesFn(ctx)
	}

	var allEntries []EntryResult
	for _, e := range m.Entries {
		isManaged := strings.HasPrefix(e.Comment, "wl|")
		h := e.Comment
		if isManaged {
			h = strings.TrimPrefix(e.Comment, "wl|")
		}
		allEntries = append(allEntries, EntryResult{
			ID:            e.ID,
			Address:       e.Address,
			List:          e.List,
			Comment:       e.Comment,
			Hostname:      h,
			Timeout:       e.Timeout,
			IsManaged:     isManaged,
			WinboxAllowed: m.hasWinboxAddressLocked(e.Address),
		})
	}

	return allEntries, nil
}
