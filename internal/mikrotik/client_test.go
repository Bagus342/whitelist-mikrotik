package mikrotik

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMockClient_WhitelistAndRemove(t *testing.T) {
	mock := NewMockClient()
	ctx := context.Background()

	ip := "203.0.113.10"

	// 1. First add
	res, err := mock.Whitelist(ctx, ip)
	if err != nil {
		t.Fatalf("unexpected error on Whitelist add: %v", err)
	}
	if res.Action != ActionAdded {
		t.Errorf("expected action %v, got %v", ActionAdded, res.Action)
	}
	if res.IP != ip {
		t.Errorf("expected IP %s, got %s", ip, res.IP)
	}
	if res.ExpiresAt.Before(time.Now()) {
		t.Errorf("expected future expiry time, got %v", res.ExpiresAt)
	}
	if res.RemovedFromAbuse {
		t.Errorf("expected RemovedFromAbuse to be false, got true")
	}

	// 2. Extend existing
	resExtend, err := mock.Whitelist(ctx, ip)
	if err != nil {
		t.Fatalf("unexpected error on Whitelist extend: %v", err)
	}
	if resExtend.Action != ActionExtended {
		t.Errorf("expected action %v, got %v", ActionExtended, resExtend.Action)
	}
	if resExtend.RemovedFromAbuse {
		t.Errorf("expected RemovedFromAbuse to be false, got true")
	}

	// 3. Remove managed entry
	if err := mock.Remove(ctx, ip); err != nil {
		t.Fatalf("unexpected error on Remove: %v", err)
	}

	// 4. Remove not found
	if err := mock.Remove(ctx, ip); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 5. Protected / admin entry (no "wl|" prefix)
	adminIP := "203.0.113.99"
	mock.Entries[adminIP] = MockEntry{
		ID:      "*99",
		List:    "remote-whitelist",
		Address: adminIP,
		Comment: "admin static rule",
	}

	if err := mock.Remove(ctx, adminIP); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("expected ErrNotManaged for admin entry, got %v", err)
	}

	// 6. Ping check
	if err := mock.Ping(ctx); err != nil {
		t.Fatalf("unexpected error on Ping: %v", err)
	}
}

func TestMockClient_Whitelist_PortForwardAbuseRemoval(t *testing.T) {
	mock := NewMockClient()
	ctx := context.Background()

	abuseIP := "78.135.83.166"

	// 1. IP exists in port-forward-abuse list
	mock.AddAbuseEntry(abuseIP)
	if _, exists := mock.AbuseEntries[abuseIP]; !exists {
		t.Fatalf("expected %s to be in AbuseEntries", abuseIP)
	}

	// 2. Perform Whitelist
	res, err := mock.Whitelist(ctx, abuseIP)
	if err != nil {
		t.Fatalf("unexpected error on Whitelist: %v", err)
	}

	if !res.RemovedFromAbuse {
		t.Errorf("expected RemovedFromAbuse=true, got false")
	}
	if res.Action != ActionAdded {
		t.Errorf("expected ActionAdded, got %v", res.Action)
	}
	if res.IP != abuseIP {
		t.Errorf("expected IP %s, got %s", abuseIP, res.IP)
	}

	// 3. Verify removed from AbuseEntries
	if _, exists := mock.AbuseEntries[abuseIP]; exists {
		t.Errorf("expected %s to be removed from AbuseEntries, but still exists", abuseIP)
	}

	// 4. Verify added to Entries (whitelist)
	entry, exists := mock.Entries[abuseIP]
	if !exists {
		t.Fatalf("expected %s to be in Entries, but not found", abuseIP)
	}
	if entry.List != "remote-whitelist" {
		t.Errorf("expected list remote-whitelist, got %s", entry.List)
	}
}

func TestMockClient_Whitelist_PortForwardAbuseRemoval_ExistingWhitelist(t *testing.T) {
	mock := NewMockClient()
	ctx := context.Background()

	ip := "88.201.104.150"

	// Pre-populate both in port-forward-abuse and in remote-whitelist
	mock.AddAbuseEntry(ip)
	mock.Entries[ip] = MockEntry{
		ID:        "*existing",
		List:      "remote-whitelist",
		Address:   ip,
		Comment:   "wl|" + time.Now().Add(-1*time.Hour).Format(time.RFC3339),
		Timeout:   "7h",
		ExpiresAt: time.Now().Add(7 * time.Hour),
	}

	// Perform Whitelist
	res, err := mock.Whitelist(ctx, ip)
	if err != nil {
		t.Fatalf("unexpected error on Whitelist: %v", err)
	}

	if !res.RemovedFromAbuse {
		t.Errorf("expected RemovedFromAbuse=true, got false")
	}
	if res.Action != ActionExtended {
		t.Errorf("expected ActionExtended, got %v", res.Action)
	}

	// Verify removed from AbuseEntries
	if _, exists := mock.AbuseEntries[ip]; exists {
		t.Errorf("expected %s to be removed from AbuseEntries", ip)
	}

	// Verify still in Entries (whitelist)
	if _, exists := mock.Entries[ip]; !exists {
		t.Errorf("expected %s to remain in Entries", ip)
	}
}
