package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	ListenAddr               string
	MikrotikHost             string
	MikrotikPort             int
	MikrotikUser             string
	MikrotikPassword         string
	AuthBearerToken          string
	WhitelistListName        string
	PortForwardAbuseListName string
	WhitelistTTL             string        // Format accepted by RouterOS (e.g., "8h")
	WhitelistDuration        time.Duration // Parsed Go duration for expiry calculation
	OfficePublicIPs          []netip.Prefix
	AllowIPv6                bool
	Timezone                 string
	Location                 *time.Location

	// Authentik / OIDC single sign-on (the only way to access the Web UI)
	AuthentikIssuerURL     string
	AuthentikClientID      string
	AuthentikClientSecret  string
	AuthentikRedirectURL   string
	AuthentikScopes        []string
	AuthentikAllowedGroups []string
	AuthentikPostLogoutURL string
}

// Load reads and validates configuration from environment variables.
func Load() (*Config, error) {
	listenAddr := getEnv("LISTEN_ADDR", "127.0.0.1:8080")

	mkHost := os.Getenv("MIKROTIK_HOST")
	if strings.TrimSpace(mkHost) == "" {
		return nil, errors.New("MIKROTIK_HOST is required")
	}

	mkPortStr := getEnv("MIKROTIK_PORT", "8728")
	mkPort, err := strconv.Atoi(mkPortStr)
	if err != nil || mkPort <= 0 || mkPort > 65535 {
		return nil, fmt.Errorf("invalid MIKROTIK_PORT: %s", mkPortStr)
	}

	mkUser := os.Getenv("MIKROTIK_USER")
	if strings.TrimSpace(mkUser) == "" {
		return nil, errors.New("MIKROTIK_USER is required")
	}

	mkPassword := os.Getenv("MIKROTIK_PASSWORD")
	if mkPassword == "" {
		return nil, errors.New("MIKROTIK_PASSWORD is required")
	}

	authBearerToken := getEnv("AUTH_BEARER_TOKEN", "")

	listName := getEnv("WHITELIST_LIST_NAME", "remote-whitelist")
	if strings.TrimSpace(listName) == "" {
		return nil, errors.New("WHITELIST_LIST_NAME cannot be empty")
	}

	abuseListName := getEnv("PORT_FORWARD_ABUSE_LIST_NAME", "port-forward-abuse")
	if strings.TrimSpace(abuseListName) == "" {
		return nil, errors.New("PORT_FORWARD_ABUSE_LIST_NAME cannot be empty")
	}

	ttlStr := getEnv("WHITELIST_TTL", "8h")
	duration, err := parseTTL(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid WHITELIST_TTL: %w", err)
	}

	allowIPv6 := false
	if v := os.Getenv("ALLOW_IPV6"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ALLOW_IPV6: %w", err)
		}
		allowIPv6 = b
	}

	tzStr := getEnv("TZ", "Asia/Jakarta")
	loc, err := time.LoadLocation(tzStr)
	if err != nil {
		return nil, fmt.Errorf("invalid TZ (%s): %w", tzStr, err)
	}

	officeIPsStr := os.Getenv("OFFICE_PUBLIC_IPS")
	officeIPs, err := parseOfficeIPs(officeIPsStr)
	if err != nil {
		return nil, fmt.Errorf("invalid OFFICE_PUBLIC_IPS: %w", err)
	}

	akIssuer := getEnv("AUTHENTIK_ISSUER_URL", "")
	if akIssuer == "" {
		return nil, errors.New("AUTHENTIK_ISSUER_URL is required")
	}
	if err := requireHTTPURL("AUTHENTIK_ISSUER_URL", akIssuer); err != nil {
		return nil, err
	}
	akClientID := getEnv("AUTHENTIK_CLIENT_ID", "")
	if akClientID == "" {
		return nil, errors.New("AUTHENTIK_CLIENT_ID is required")
	}
	akClientSecret := strings.TrimSpace(os.Getenv("AUTHENTIK_CLIENT_SECRET"))
	akRedirect := getEnv("AUTHENTIK_REDIRECT_URL", "")
	if akRedirect == "" {
		return nil, errors.New("AUTHENTIK_REDIRECT_URL is required")
	}
	if err := requireHTTPURL("AUTHENTIK_REDIRECT_URL", akRedirect); err != nil {
		return nil, err
	}
	akPostLogout := getEnv("AUTHENTIK_POST_LOGOUT_URL", "")
	if akPostLogout != "" {
		if err := requireHTTPURL("AUTHENTIK_POST_LOGOUT_URL", akPostLogout); err != nil {
			return nil, err
		}
	}

	return &Config{
		ListenAddr:               listenAddr,
		MikrotikHost:             mkHost,
		MikrotikPort:             mkPort,
		MikrotikUser:             mkUser,
		MikrotikPassword:         mkPassword,
		AuthBearerToken:          authBearerToken,
		WhitelistListName:        listName,
		PortForwardAbuseListName: abuseListName,
		WhitelistTTL:             ttlStr,
		WhitelistDuration:        duration,
		OfficePublicIPs:          officeIPs,
		AllowIPv6:                allowIPv6,
		Timezone:                 tzStr,
		Location:                 loc,

		AuthentikIssuerURL:     akIssuer,
		AuthentikClientID:      akClientID,
		AuthentikClientSecret:  akClientSecret,
		AuthentikRedirectURL:   akRedirect,
		AuthentikScopes:        splitList(getEnv("AUTHENTIK_SCOPES", "openid profile email"), " ,"),
		AuthentikAllowedGroups: splitList(os.Getenv("AUTHENTIK_ALLOWED_GROUPS"), ","),
		AuthentikPostLogoutURL: akPostLogout,
	}, nil
}

// String masks sensitive fields so Config can be safely logged.
func (c *Config) String() string {
	var officeIPs []string
	for _, p := range c.OfficePublicIPs {
		officeIPs = append(officeIPs, p.String())
	}
	authStatus := "disabled"
	if c.AuthBearerToken != "" {
		authStatus = "enabled"
	}
	authentik := fmt.Sprintf("%s(client=%s groups=[%s])", c.AuthentikIssuerURL, c.AuthentikClientID,
		strings.Join(c.AuthentikAllowedGroups, ","))
	return fmt.Sprintf(
		"ListenAddr=%s MikrotikHost=%s:%d MikrotikUser=%s AuthBearer=%s WhitelistListName=%s PortForwardAbuseListName=%s WhitelistTTL=%s OfficeIPs=[%s] AllowIPv6=%t TZ=%s Authentik=%s",
		c.ListenAddr, c.MikrotikHost, c.MikrotikPort, c.MikrotikUser, authStatus, c.WhitelistListName, c.PortForwardAbuseListName, c.WhitelistTTL,
		strings.Join(officeIPs, ","), c.AllowIPv6, c.Timezone, authentik,
	)
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

// splitList splits s on any of the separator characters, dropping empty items.
func splitList(s, seps string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// requireHTTPURL ensures v is an absolute http(s) URL.
func requireHTTPURL(name, v string) error {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s must be an absolute http(s) URL, got %q", name, v)
	}
	return nil
}

// parseTTL parses string durations like "8h", "30m", or "1d".
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}

	// Handle days suffix like '1d' or '2d'
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid days format: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("duration must be greater than zero")
	}
	return d, nil
}

// parseOfficeIPs parses comma-separated IPs or CIDRs into netip.Prefix.
func parseOfficeIPs(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))

	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}

		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR '%s': %w", item, err)
			}
			prefixes = append(prefixes, prefix)
		} else {
			addr, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("invalid IP '%s': %w", item, err)
			}
			// Convert single address to a /32 (IPv4) or /128 (IPv6) prefix
			prefix := netip.PrefixFrom(addr, addr.BitLen())
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes, nil
}
