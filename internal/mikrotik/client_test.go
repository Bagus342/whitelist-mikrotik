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

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"laptop-budi", "laptop-budi"},
		{"DESKTOP-123_abc", "DESKTOP-123_abc"},
		{"my.host.name.", "my.host.name"},
		{"pipe|injection", "pipe-injection"},
		{"with spaces here", "with-spaces-here"},
		{"bad!@#chars$%", "badchars"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		got := SanitizeHostname(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMockClient_Whitelist_HostnameComment(t *testing.T) {
	mock := NewMockClient()
	ctx := context.Background()

	ip := "203.0.113.88"

	// 1. Whitelist with custom hostname
	res, err := mock.Whitelist(ctx, ip, "macbook-pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Hostname != "macbook-pro" {
		t.Errorf("expected Hostname macbook-pro, got %s", res.Hostname)
	}

	entry, ok := mock.Entries[ip]
	if !ok {
		t.Fatalf("expected entry for %s", ip)
	}

	if entry.Comment != "wl|macbook-pro" {
		t.Errorf("expected comment 'wl|macbook-pro', got %q", entry.Comment)
	}

	// 2. Extend with new hostname
	resExtend, err := mock.Whitelist(ctx, ip, "macbook-pro-updated")
	if err != nil {
		t.Fatalf("unexpected error on extend: %v", err)
	}
	if resExtend.Hostname != "macbook-pro-updated" {
		t.Errorf("expected Hostname macbook-pro-updated, got %s", resExtend.Hostname)
	}

	entryUpdated := mock.Entries[ip]
	if entryUpdated.Comment != "wl|macbook-pro-updated" {
		t.Errorf("expected updated comment 'wl|macbook-pro-updated', got %q", entryUpdated.Comment)
	}

	// 3. Whitelist without hostname -> defaults to IP
	ip2 := "203.0.113.89"
	res2, err := mock.Whitelist(ctx, ip2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res2.Hostname != ip2 {
		t.Errorf("expected Hostname %s, got %s", ip2, res2.Hostname)
	}

	entry2 := mock.Entries[ip2]
	if entry2.Comment != "wl|"+ip2 {
		t.Errorf("expected comment 'wl|%s', got %q", ip2, entry2.Comment)
	}
}

func TestFormatWinboxCIDR(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"180.252.167.103", "180.252.167.103/32"},
		{" 180.252.167.103 ", "180.252.167.103/32"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.1/32", "10.0.0.1/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/64", "2001:db8::/64"},
	}

	for _, tt := range tests {
		got := FormatWinboxCIDR(tt.input)
		if got != tt.expected {
			t.Errorf("FormatWinboxCIDR(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseAddressList(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"   ", nil},
		{"192.168.1.0/24", []string{"192.168.1.0/24"}},
		{"192.168.1.0/24, 10.0.0.0/8", []string{"192.168.1.0/24", "10.0.0.0/8"}},
		{",192.168.1.0/24,,10.0.0.0/8,", []string{"192.168.1.0/24", "10.0.0.0/8"}},
	}

	for _, tt := range tests {
		got := parseAddressList(tt.input)
		if len(got) != len(tt.expected) {
			t.Fatalf("parseAddressList(%q) len = %d; want %d", tt.input, len(got), len(tt.expected))
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("parseAddressList(%q)[%d] = %q; want %q", tt.input, i, got[i], tt.expected[i])
			}
		}
	}
}

func TestMockClient_AllowWinbox_And_RemoveWinbox(t *testing.T) {
	mock := NewMockClient()
	ctx := context.Background()

	ip := "180.252.167.103"

	// 1. Initially not present
	if mock.HasWinboxAddress(ip) {
		t.Fatalf("expected HasWinboxAddress false initially")
	}

	// 2. AllowWinbox adds /32
	if err := mock.AllowWinbox(ctx, ip); err != nil {
		t.Fatalf("unexpected error on AllowWinbox: %v", err)
	}
	if !mock.HasWinboxAddress(ip) {
		t.Errorf("expected HasWinboxAddress true after allow")
	}
	if len(mock.WinboxAddresses) != 1 || mock.WinboxAddresses[0] != "180.252.167.103/32" {
		t.Errorf("expected [180.252.167.103/32], got %v", mock.WinboxAddresses)
	}

	// 3. AllowWinbox again is idempotent (does not duplicate)
	if err := mock.AllowWinbox(ctx, ip); err != nil {
		t.Fatalf("unexpected error on second AllowWinbox: %v", err)
	}
	if len(mock.WinboxAddresses) != 1 {
		t.Errorf("expected still 1 entry, got %v", mock.WinboxAddresses)
	}

	// 4. Add another IP
	ip2 := "203.0.113.50"
	if err := mock.AllowWinbox(ctx, ip2); err != nil {
		t.Fatalf("unexpected error on AllowWinbox ip2: %v", err)
	}
	if len(mock.WinboxAddresses) != 2 {
		t.Errorf("expected 2 entries, got %v", mock.WinboxAddresses)
	}

	// 5. Remove first IP
	if err := mock.RemoveWinbox(ctx, ip); err != nil {
		t.Fatalf("unexpected error on RemoveWinbox: %v", err)
	}
	if mock.HasWinboxAddress(ip) {
		t.Errorf("expected ip to be removed from winbox")
	}
	if !mock.HasWinboxAddress(ip2) {
		t.Errorf("expected ip2 to remain in winbox")
	}

	// 6. Remove non-existent IP (no-op, no error)
	if err := mock.RemoveWinbox(ctx, "1.1.1.1"); err != nil {
		t.Fatalf("unexpected error on RemoveWinbox nonexistent: %v", err)
	}
}

func TestDetectISP(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"empty IP", "", "Tidak Diketahui"},
		{"malformed IP", "invalid-ip-string", "Tidak Diketahui"},
		{"loopback IPv4", "127.0.0.1", "Jaringan Lokal (LAN)"},
		{"private 192.168", "192.168.1.50", "Jaringan Lokal (LAN)"},
		{"private 10.x", "10.0.0.1", "Jaringan Lokal (LAN)"},
		{"loopback IPv6", "::1", "Jaringan Lokal (LAN)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectISP(ctx, tt.ip)
			if got != tt.expected {
				t.Errorf("DetectISP(%q) = %q, expected %q", tt.ip, got, tt.expected)
			}
		})
	}

	// For documentation public IP TEST-NET, it should return a non-empty string without error
	gotPublic := DetectISP(ctx, "203.0.113.10")
	if gotPublic == "" {
		t.Errorf("DetectISP public returned empty string")
	}
}

func TestMockClient_GetStatus_IncludesISP(t *testing.T) {
	mock := NewMockClient()
	ctx := context.Background()

	status, err := mock.GetStatus(ctx, "192.168.88.25")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ISP != "Jaringan Lokal (LAN)" {
		t.Errorf("expected ISP 'Jaringan Lokal (LAN)', got %q", status.ISP)
	}
}

func TestFormatISPFromGeoIP(t *testing.T) {
	tests := []struct {
		name        string
		isp         string
		org         string
		domain      string
		asn         string
		country     string
		countryCode string
		city        string
		expected    string
	}{
		{
			name:        "Cloudflare ASN",
			isp:         "Cloudflare, Inc.",
			org:         "Cloudflare, Inc.",
			asn:         "13335",
			countryCode: "US",
			expected:    "Cloudflare",
		},
		{
			name:        "Wasabi S3 ASN",
			isp:         "Wasabi Systems",
			org:         "Wasabi Systems",
			asn:         "395717",
			countryCode: "US",
			expected:    "Wasabi S3",
		},
		{
			name:        "Moratelindo Oxygen",
			isp:         "PT Mora Telematika Indonesia",
			org:         "PT Mora Telematika Indonesia",
			domain:      "moratelindo.co.id",
			asn:         "23947",
			countryCode: "ID",
			city:        "Jakarta",
			expected:    "Oxygen.id (Moratelindo)",
		},
		{
			name:        "Telkom Indonesia",
			isp:         "Telkom Indonesia",
			org:         "PT Telkom Indonesia",
			domain:      "telkom.co.id",
			asn:         "17974",
			countryCode: "ID",
			city:        "Jakarta",
			expected:    "Telkom Indonesia (IndiHome)",
		},
		{
			name:        "Telkomsel",
			isp:         "PT Telekomunikasi Selular",
			org:         "Telkomsel",
			domain:      "telkomsel.com",
			asn:         "24203",
			countryCode: "ID",
			expected:    "Telkomsel",
		},
		{
			name:        "Biznet",
			isp:         "Biznet Networks",
			org:         "PT Supra Primatama Nusantara",
			domain:      "biznetnetworks.com",
			asn:         "17451",
			countryCode: "ID",
			expected:    "Biznet Networks",
		},
		{
			name:        "First Media",
			isp:         "First Media",
			org:         "PT Link Net Tbk",
			domain:      "firstmedia.com",
			asn:         "23700",
			countryCode: "ID",
			expected:    "First Media (LinkNet)",
		},
		{
			name:        "Foreign Cloud in Indonesia",
			isp:         "Google LLC",
			org:         "Google Cloud Platform",
			domain:      "google.com",
			asn:         "15169",
			countryCode: "ID",
			country:     "Indonesia",
			expected:    "Google Cloud (ID)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatISPFromGeoIP(tt.isp, tt.org, tt.domain, tt.asn, tt.country, tt.countryCode, tt.city)
			if got != tt.expected {
				t.Errorf("FormatISPFromGeoIP() = %q, expected %q", got, tt.expected)
			}
		})
	}
}
