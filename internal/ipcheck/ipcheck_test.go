package ipcheck

import (
	"errors"
	"net/netip"
	"testing"
)

func TestValidator_Validate(t *testing.T) {
	officePrefixes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.50/32"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}

	tests := []struct {
		name      string
		rawIP     string
		allowIPv6 bool
		officeIPs []netip.Prefix
		wantErr   error
		wantAddr  string
	}{
		// 1. IP valid IPv4
		{
			name:      "valid IPv4",
			rawIP:     "203.0.113.195",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   nil,
			wantAddr:  "203.0.113.195",
		},
		// 2. Trailing newline / whitespace
		{
			name:      "trailing newline and space",
			rawIP:     "  203.0.113.195\n\r\t",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   nil,
			wantAddr:  "203.0.113.195",
		},
		// 3. Kosong (empty or only whitespace)
		{
			name:      "empty string",
			rawIP:     "",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPRequired,
		},
		{
			name:      "whitespace only",
			rawIP:     "   \n  ",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPRequired,
		},
		// 4. Format salah
		{
			name:      "malformed IP letters",
			rawIP:     "invalid-ip",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPInvalid,
		},
		{
			name:      "malformed octet range",
			rawIP:     "256.1.2.3",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPInvalid,
		},
		{
			name:      "IP with CIDR subnet",
			rawIP:     "203.0.113.5/24",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPInvalid,
		},
		// 5. Private IPv4 (RFC 1918)
		{
			name:      "private 10.x",
			rawIP:     "10.10.10.10",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "private 172.16.x",
			rawIP:     "172.16.5.1",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "private 192.168.x",
			rawIP:     "192.168.1.100",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		// 6. CGNAT 100.64.0.0/10 (RFC 6598)
		{
			name:      "CGNAT lower bound",
			rawIP:     "100.64.0.1",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "CGNAT upper bound",
			rawIP:     "100.127.255.254",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		// 7. Loopback
		{
			name:      "loopback IPv4 127.0.0.1",
			rawIP:     "127.0.0.1",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "loopback IPv4 127.1.2.3",
			rawIP:     "127.1.2.3",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		// 8. Link-Local & Multicast & Unspecified
		{
			name:      "link-local 169.254.x",
			rawIP:     "169.254.10.5",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "multicast 224.0.0.1",
			rawIP:     "224.0.0.1",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "unspecified 0.0.0.0",
			rawIP:     "0.0.0.0",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		// 9. IP Publik Kantor Sendiri (OFFICE_PUBLIC_IPS)
		{
			name:      "office public single IP",
			rawIP:     "203.0.113.50",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "office public CIDR subnet member",
			rawIP:     "198.51.100.25",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		// 10. IPv6 saat flag off
		{
			name:      "IPv6 with allowIPv6=false",
			rawIP:     "2001:db8::1",
			allowIPv6: false,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		// 11. IPv6 saat flag on
		{
			name:      "valid public IPv6 with allowIPv6=true",
			rawIP:     "2001:db8::1",
			allowIPv6: true,
			officeIPs: officePrefixes,
			wantErr:   nil,
			wantAddr:  "2001:db8::1",
		},
		{
			name:      "IPv6 loopback ::1 with allowIPv6=true",
			rawIP:     "::1",
			allowIPv6: true,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "IPv6 private ULA fc00::1 with allowIPv6=true",
			rawIP:     "fd00::1",
			allowIPv6: true,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
		{
			name:      "IPv6 link-local fe80::1 with allowIPv6=true",
			rawIP:     "fe80::1",
			allowIPv6: true,
			officeIPs: officePrefixes,
			wantErr:   ErrIPForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator(tt.allowIPv6, tt.officeIPs)
			addr, err := validator.Validate(tt.rawIP)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if addr.String() != tt.wantAddr {
					t.Fatalf("expected addr %s, got %s", tt.wantAddr, addr.String())
				}
			}
		})
	}
}
