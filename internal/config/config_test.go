package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func setEnvs(t *testing.T, envs map[string]string) {
	t.Helper()
	for k, v := range envs {
		t.Setenv(k, v)
	}
}

func TestLoad_Success(t *testing.T) {
	setEnvs(t, map[string]string{
		"LISTEN_ADDR":                  "0.0.0.0:9090",
		"MIKROTIK_HOST":                "192.168.88.1",
		"MIKROTIK_PORT":                "8728",
		"MIKROTIK_USER":                "api-user",
		"MIKROTIK_PASSWORD":            "secretpassword",
		"AUTH_BEARER_TOKEN":            "supersecrettoken",
		"WHITELIST_LIST_NAME":          "custom-list",
		"PORT_FORWARD_ABUSE_LIST_NAME": "custom-abuse-list",
		"WHITELIST_TTL":                "12h",
		"OFFICE_PUBLIC_IPS":            "203.0.113.10,198.51.100.0/24",
		"ALLOW_IPV6":                   "true",
		"TZ":                           "Asia/Jakarta",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != "0.0.0.0:9090" {
		t.Errorf("expected 0.0.0.0:9090, got %s", cfg.ListenAddr)
	}
	if cfg.MikrotikHost != "192.168.88.1" {
		t.Errorf("expected 192.168.88.1, got %s", cfg.MikrotikHost)
	}
	if cfg.MikrotikPort != 8728 {
		t.Errorf("expected 8728, got %d", cfg.MikrotikPort)
	}
	if cfg.MikrotikUser != "api-user" {
		t.Errorf("expected api-user, got %s", cfg.MikrotikUser)
	}
	if cfg.MikrotikPassword != "secretpassword" {
		t.Errorf("expected secretpassword, got %s", cfg.MikrotikPassword)
	}
	if cfg.AuthBearerToken != "supersecrettoken" {
		t.Errorf("expected supersecrettoken, got %s", cfg.AuthBearerToken)
	}
	if cfg.WhitelistListName != "custom-list" {
		t.Errorf("expected custom-list, got %s", cfg.WhitelistListName)
	}
	if cfg.PortForwardAbuseListName != "custom-abuse-list" {
		t.Errorf("expected custom-abuse-list, got %s", cfg.PortForwardAbuseListName)
	}
	if cfg.WhitelistDuration != 12*time.Hour {
		t.Errorf("expected 12h, got %v", cfg.WhitelistDuration)
	}
	if len(cfg.OfficePublicIPs) != 2 {
		t.Fatalf("expected 2 office prefixes, got %d", len(cfg.OfficePublicIPs))
	}
	if !cfg.AllowIPv6 {
		t.Errorf("expected AllowIPv6=true")
	}
	if cfg.Location.String() != "Asia/Jakarta" {
		t.Errorf("expected Asia/Jakarta, got %v", cfg.Location)
	}

	// Ensure password and token are not present in String() output
	str := cfg.String()
	if strings.Contains(str, "secretpassword") {
		t.Errorf("String() contains plain password! Got: %s", str)
	}
	if strings.Contains(str, "supersecrettoken") {
		t.Errorf("String() contains plain bearer token! Got: %s", str)
	}
	if !strings.Contains(str, "AuthBearer=enabled") {
		t.Errorf("expected AuthBearer=enabled in String(), got: %s", str)
	}
}

func TestLoad_Defaults(t *testing.T) {
	// Set only required fields
	setEnvs(t, map[string]string{
		"MIKROTIK_HOST":     "10.0.0.1",
		"MIKROTIK_USER":     "admin",
		"MIKROTIK_PASSWORD": "pass",
	})
	// Unset optional fields to test defaults
	for _, k := range []string{
		"LISTEN_ADDR", "MIKROTIK_PORT", "AUTH_BEARER_TOKEN", "WHITELIST_LIST_NAME", "PORT_FORWARD_ABUSE_LIST_NAME",
		"WHITELIST_TTL", "OFFICE_PUBLIC_IPS", "ALLOW_IPV6", "TZ",
	} {
		os.Unsetenv(k)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("expected default 127.0.0.1:8080, got %s", cfg.ListenAddr)
	}
	if cfg.AuthBearerToken != "" {
		t.Errorf("expected default AuthBearerToken='', got %s", cfg.AuthBearerToken)
	}
	if cfg.MikrotikPort != 8728 {
		t.Errorf("expected default 8728, got %d", cfg.MikrotikPort)
	}
	if cfg.WhitelistListName != "remote-whitelist" {
		t.Errorf("expected default remote-whitelist, got %s", cfg.WhitelistListName)
	}
	if cfg.PortForwardAbuseListName != "port-forward-abuse" {
		t.Errorf("expected default port-forward-abuse, got %s", cfg.PortForwardAbuseListName)
	}
	if cfg.WhitelistDuration != 8*time.Hour {
		t.Errorf("expected default 8h, got %v", cfg.WhitelistDuration)
	}
	if cfg.AllowIPv6 {
		t.Errorf("expected default AllowIPv6=false")
	}
	if cfg.Location.String() != "Asia/Jakarta" {
		t.Errorf("expected default TZ Asia/Jakarta, got %v", cfg.Location)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	tests := []struct {
		name string
		envs map[string]string
	}{
		{"missing host", map[string]string{"MIKROTIK_USER": "u", "MIKROTIK_PASSWORD": "p"}},
		{"missing user", map[string]string{"MIKROTIK_HOST": "h", "MIKROTIK_PASSWORD": "p"}},
		{"missing password", map[string]string{"MIKROTIK_HOST": "h", "MIKROTIK_USER": "u"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			setEnvs(t, tt.envs)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"8h", 8 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"1d", 24 * time.Hour, false},
		{"2d", 48 * time.Hour, false},
		{"0s", 0, true},
		{"-5m", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := parseTTL(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseTTL(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("parseTTL(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
