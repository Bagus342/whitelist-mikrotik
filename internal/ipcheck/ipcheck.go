package ipcheck

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	// ErrIPRequired indicates that the IP field was empty or only whitespace.
	ErrIPRequired = errors.New("ERROR ip wajib diisi")

	// ErrIPInvalid indicates that the IP string could not be parsed as an IP address.
	ErrIPInvalid = errors.New("ERROR ip tidak valid")

	// ErrIPForbidden indicates that the IP belongs to a prohibited range or matches office public IPs.
	ErrIPForbidden = errors.New("ERROR ip tidak diizinkan")

	// cgnatPrefix represents Carrier-Grade NAT (RFC 6598): 100.64.0.0/10.
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
)

// Validator validates IP addresses against security policies and whitelist rules.
type Validator struct {
	allowIPv6       bool
	officePublicIPs []netip.Prefix
}

// NewValidator creates a new Validator with the given policy options.
func NewValidator(allowIPv6 bool, officePublicIPs []netip.Prefix) *Validator {
	return &Validator{
		allowIPv6:       allowIPv6,
		officePublicIPs: officePublicIPs,
	}
}

// Validate checks rawIP against all validation rules.
// On success, returns the normalized netip.Addr and nil error.
// On failure, returns one of ErrIPRequired, ErrIPInvalid, or ErrIPForbidden.
func (v *Validator) Validate(rawIP string) (netip.Addr, error) {
	// 1. Trim whitespace and newlines (e.g. from curl https://ifconfig.me)
	trimmed := strings.TrimSpace(rawIP)

	// 2. IP empty or not provided
	if trimmed == "" {
		return netip.Addr{}, ErrIPRequired
	}

	// 3. Parse with netip.ParseAddr
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Addr{}, ErrIPInvalid
	}

	// Unmap IPv4-mapped IPv6 address (e.g., ::ffff:203.0.113.5 -> 203.0.113.5)
	addr = addr.Unmap()

	// 4. IPv6 check: IPv4 only by default unless allowIPv6 is true
	if addr.Is6() && !v.allowIPv6 {
		return netip.Addr{}, ErrIPForbidden
	}

	// 5. Prohibited IP checks:
	// - Unspecified (0.0.0.0 or ::)
	// - Loopback (127.0.0.0/8 or ::1)
	// - Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	// - Link-local (169.254.0.0/16, fe80::/10, etc.)
	// - Multicast
	// - CGNAT (100.64.0.0/10)
	if addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		cgnatPrefix.Contains(addr) {
		return netip.Addr{}, ErrIPForbidden
	}

	// Office public IPs check
	for _, prefix := range v.officePublicIPs {
		if prefix.Contains(addr) {
			return netip.Addr{}, ErrIPForbidden
		}
	}

	return addr, nil
}
