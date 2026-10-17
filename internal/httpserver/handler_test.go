package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"whitelist-mikrotik/internal/ipcheck"
	"whitelist-mikrotik/internal/mikrotik"
)

func setupTestServer() (*Handler, *mikrotik.MockClient, http.Handler) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	validator := ipcheck.NewValidator(false, []netip.Prefix{
		netip.MustParsePrefix("203.0.113.100/32"),
	})
	mockMk := mikrotik.NewMockClient()
	handler := NewHandler(validator, mockMk, logger)
	router := SetupRouter(handler, "", logger)
	return handler, mockMk, router
}

func TestHandler_PostWhitelist_AddNew(t *testing.T) {
	_, _, router := setupTestServer()

	form := url.Values{}
	form.Set("ip", "203.0.113.15")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.HasPrefix(body, "OK ip=203.0.113.15 expires=") {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestHandler_PostWhitelist_ExtendExisting(t *testing.T) {
	_, mockMk, router := setupTestServer()

	// Pre-populate mock entry
	ip := "203.0.113.15"
	mockMk.Entries[ip] = mikrotik.MockEntry{
		ID:      "*1",
		List:    "remote-whitelist",
		Address: ip,
		Comment: "wl|" + time.Now().Format(time.RFC3339),
	}

	form := url.Values{}
	form.Set("ip", ip)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.HasPrefix(body, "OK ip=203.0.113.15 expires=") {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestHandler_PostWhitelist_JSON(t *testing.T) {
	_, _, router := setupTestServer()

	form := url.Values{}
	form.Set("ip", "203.0.113.20")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Status != "ok" || resp.IP != "203.0.113.20" || resp.Action != "added" || resp.Expires == "" {
		t.Errorf("unexpected JSON payload: %+v", resp)
	}
}

func TestHandler_DeleteWhitelist_Success(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.25"
	mockMk.Entries[ip] = mikrotik.MockEntry{
		ID:      "*2",
		List:    "remote-whitelist",
		Address: ip,
		Comment: "wl|" + time.Now().Format(time.RFC3339),
	}

	form := url.Values{}
	form.Set("ip", ip)

	req := httptest.NewRequest(http.MethodDelete, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if body != "OK ip=203.0.113.25 action=removed" {
		t.Errorf("expected 'OK ip=203.0.113.25 action=removed', got: %s", body)
	}
}

func TestHandler_DeleteWhitelist_NonManagedRejected(t *testing.T) {
	_, mockMk, router := setupTestServer()

	adminIP := "203.0.113.30"
	mockMk.Entries[adminIP] = mikrotik.MockEntry{
		ID:      "*3",
		List:    "remote-whitelist",
		Address: adminIP,
		Comment: "manual admin entry",
	}

	form := url.Values{}
	form.Set("ip", adminIP)

	req := httptest.NewRequest(http.MethodDelete, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", w.Code)
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.Contains(body, "ERROR ip tidak diizinkan untuk dihapus") {
		t.Errorf("expected 'ERROR ip tidak diizinkan untuk dihapus', got: %s", body)
	}
}

func TestHandler_MikrotikError_502NoLeak(t *testing.T) {
	_, mockMk, router := setupTestServer()

	// Configure mock to simulate an internal error with sensitive details
	mockMk.WhitelistFn = func(ctx context.Context, ip string, hostname ...string) (*mikrotik.WhitelistResult, error) {
		return nil, errors.New("cannot connect to 192.168.88.1:8728 with user admin: secret credentials error")
	}

	form := url.Values{}
	form.Set("ip", "203.0.113.35")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502 Bad Gateway, got %d", w.Code)
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.HasPrefix(body, "ERROR internal (req=") {
		t.Errorf("expected 'ERROR internal (req=...)', got: %s", body)
	}

	// Crucial check: make sure internal MikroTik error details are NOT leaked to client!
	if strings.Contains(body, "192.168.88.1") || strings.Contains(body, "credentials") {
		t.Errorf("response leaked sensitive internal details: %s", body)
	}
}

func TestHandler_IPValidationFailures(t *testing.T) {
	_, _, router := setupTestServer()

	tests := []struct {
		name       string
		formVal    string
		hasField   bool
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "missing ip field",
			formVal:    "",
			hasField:   false,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "ERROR ip wajib diisi",
		},
		{
			name:       "empty ip field",
			formVal:    "   \n",
			hasField:   true,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "ERROR ip wajib diisi",
		},
		{
			name:       "invalid ip format",
			formVal:    "999.999.999.999",
			hasField:   true,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "ERROR ip tidak valid",
		},
		{
			name:       "private ip rejected",
			formVal:    "192.168.1.1",
			hasField:   true,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "ERROR ip tidak diizinkan",
		},
		{
			name:       "office ip rejected",
			formVal:    "203.0.113.100",
			hasField:   true,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "ERROR ip tidak diizinkan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			if tt.hasField {
				form.Set("ip", tt.formVal)
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}
			body := strings.TrimSpace(w.Body.String())
			if !strings.Contains(body, tt.wantMsg) {
				t.Errorf("expected body to contain %q, got %q", tt.wantMsg, body)
			}
		})
	}
}

func TestHandler_Healthz(t *testing.T) {
	_, mockMk, router := setupTestServer()

	// 1. Healthy
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.TrimSpace(w.Body.String()) != "ok" {
		t.Errorf("expected 'ok', got %q", w.Body.String())
	}

	// 2. Unhealthy
	mockMk.PingFn = func(ctx context.Context) error {
		return errors.New("connection refused")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "ERROR service unavailable") {
		t.Errorf("expected 'ERROR service unavailable', got %q", w2.Body.String())
	}
}

func TestHandler_PostWhitelist_TrailingNewline(t *testing.T) {
	_, _, router := setupTestServer()

	form := url.Values{}
	form.Set("ip", "203.0.113.88\n")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(w.Body.String()), "OK ip=203.0.113.88 expires=") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestHandler_BodyExceeded(t *testing.T) {
	_, _, router := setupTestServer()

	// Large body exceeding 1024 bytes
	largeData := "ip=203.0.113.10&dummy=" + strings.Repeat("A", 2048)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(largeData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized body, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ERROR body terlalu besar") {
		t.Errorf("expected body to contain 'ERROR body terlalu besar', got: %s", w.Body.String())
	}
}

func TestHandler_DeleteWhitelist_NotFound(t *testing.T) {
	_, _, router := setupTestServer()

	form := url.Values{}
	form.Set("ip", "203.0.113.99")

	req := httptest.NewRequest(http.MethodDelete, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ERROR ip tidak ditemukan") {
		t.Errorf("expected body to contain 'ERROR ip tidak ditemukan', got: %s", w.Body.String())
	}
}

func TestHandler_NotFound(t *testing.T) {
	_, _, router := setupTestServer()

	// Unknown path
	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", w.Code)
	}

	// GET on /v1/whitelist (only POST & DELETE allowed)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/whitelist", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusNotFound {
		t.Errorf("expected 404 for GET /v1/whitelist, got %d", w2.Code)
	}
}

func TestHandler_PostWhitelist_RemovedFromAbuse_Text(t *testing.T) {
	_, mockMk, router := setupTestServer()

	abuseIP := "78.135.83.166"
	mockMk.AddAbuseEntry(abuseIP)

	form := url.Values{}
	form.Set("ip", abuseIP)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.HasPrefix(body, "OK ip="+abuseIP+" expires=") {
		t.Errorf("unexpected body: %s", body)
	}

	// Verify IP was removed from abuse list
	if _, exists := mockMk.AbuseEntries[abuseIP]; exists {
		t.Errorf("expected %s to be removed from AbuseEntries, but still exists", abuseIP)
	}

	// Verify IP was added to whitelist
	if _, exists := mockMk.Entries[abuseIP]; !exists {
		t.Errorf("expected %s to be added to Entries, but not found", abuseIP)
	}
}

func TestHandler_PostWhitelist_RemovedFromAbuse_JSON(t *testing.T) {
	_, mockMk, router := setupTestServer()

	abuseIP := "88.201.104.150"
	mockMk.AddAbuseEntry(abuseIP)

	form := url.Values{}
	form.Set("ip", abuseIP)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Status != "ok" || resp.IP != abuseIP || resp.Action != "added" || !resp.RemovedFromAbuse {
		t.Errorf("unexpected JSON response: %+v", resp)
	}

	// Verify IP was removed from abuse list
	if _, exists := mockMk.AbuseEntries[abuseIP]; exists {
		t.Errorf("expected %s to be removed from AbuseEntries", abuseIP)
	}

	// Verify IP was added to whitelist
	if _, exists := mockMk.Entries[abuseIP]; !exists {
		t.Errorf("expected %s to be in Entries", abuseIP)
	}
}

func setupAuthenticatedTestServer(token string) (*Handler, *mikrotik.MockClient, http.Handler) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	validator := ipcheck.NewValidator(false, nil)
	mockMk := mikrotik.NewMockClient()
	handler := NewHandler(validator, mockMk, logger)
	router := SetupRouter(handler, token, logger)
	return handler, mockMk, router
}

func TestHandler_BearerAuth_ValidToken(t *testing.T) {
	token := "valid-secret-token"
	_, _, router := setupAuthenticatedTestServer(token)

	form := url.Values{}
	form.Set("ip", "203.0.113.55")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid bearer token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_BearerAuth_MissingToken(t *testing.T) {
	token := "valid-secret-token"
	_, _, router := setupAuthenticatedTestServer(token)

	form := url.Values{}
	form.Set("ip", "203.0.113.55")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing bearer token, got %d", w.Code)
	}
	body := strings.TrimSpace(w.Body.String())
	if body != "ERROR unauthorized" {
		t.Errorf("expected 'ERROR unauthorized', got %q", body)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("expected WWW-Authenticate header to contain Bearer")
	}
}

func TestHandler_BearerAuth_InvalidToken(t *testing.T) {
	token := "valid-secret-token"
	_, _, router := setupAuthenticatedTestServer(token)

	form := url.Values{}
	form.Set("ip", "203.0.113.55")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer invalid-wrong-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid bearer token, got %d", w.Code)
	}
}

func TestHandler_BearerAuth_MissingToken_JSON(t *testing.T) {
	token := "valid-secret-token"
	_, _, router := setupAuthenticatedTestServer(token)

	form := url.Values{}
	form.Set("ip", "203.0.113.55")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}
	if resp.Status != "error" || resp.Message != "unauthorized" {
		t.Errorf("unexpected JSON response: %+v", resp)
	}
}

func TestHandler_BearerAuth_HealthzUnprotected(t *testing.T) {
	token := "valid-secret-token"
	_, _, router := setupAuthenticatedTestServer(token)

	// Health check does not require bearer token
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /healthz without auth, got %d", w.Code)
	}
}

func TestHandler_PostWhitelist_WithCustomHostname(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.70"
	customHost := "laptop-finance"

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("hostname", customHost)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	entry, ok := mockMk.Entries[ip]
	if !ok {
		t.Fatalf("expected entry for %s", ip)
	}
	if entry.Comment != "wl|"+customHost {
		t.Errorf("expected comment 'wl|%s', got %q", customHost, entry.Comment)
	}
}

func TestHandler_PostWhitelist_WithCustomHostname_JSON(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.71"
	customHost := "pc-marketing"

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("hostname", customHost)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Hostname != customHost {
		t.Errorf("expected JSON Hostname %q, got %q", customHost, resp.Hostname)
	}

	entry, ok := mockMk.Entries[ip]
	if !ok {
		t.Fatalf("expected entry for %s", ip)
	}
	if entry.Comment != "wl|"+customHost {
		t.Errorf("expected comment 'wl|%s', got %q", customHost, entry.Comment)
	}
}

func TestHandler_PostWhitelist_WithWinbox_Flag(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.15"

	// Pass winbox as flag: "ip=...&winbox"
	bodyStr := "ip=" + ip + "&winbox"
	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.Contains(body, "winbox=allowed") {
		t.Errorf("expected response to contain 'winbox=allowed', got: %s", body)
	}

	if !mockMk.HasWinboxAddress(ip) {
		t.Errorf("expected IP %s to be allowed in mock Winbox", ip)
	}
}

func TestHandler_PostWhitelist_WithWinbox_ValueTrue(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.16"

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("winbox", "true")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.Contains(body, "winbox=allowed") {
		t.Errorf("expected response to contain 'winbox=allowed', got: %s", body)
	}

	if !mockMk.HasWinboxAddress(ip) {
		t.Errorf("expected IP %s to be allowed in mock Winbox", ip)
	}
}

func TestHandler_PostWhitelist_WithWinbox_JSON(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.17"

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("winbox", "1")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if !resp.WinboxAllowed {
		t.Errorf("expected WinboxAllowed=true, got false")
	}

	if !mockMk.HasWinboxAddress(ip) {
		t.Errorf("expected IP %s to be allowed in mock Winbox", ip)
	}
}

func TestHandler_PostWhitelist_WithJSONBody_AndWinbox(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.18"
	jsonBody := `{"ip": "203.0.113.18", "winbox": true, "hostname": "dev-box"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if !resp.WinboxAllowed {
		t.Errorf("expected WinboxAllowed=true, got false")
	}
	if resp.Hostname != "dev-box" {
		t.Errorf("expected Hostname dev-box, got %s", resp.Hostname)
	}

	if !mockMk.HasWinboxAddress(ip) {
		t.Errorf("expected IP %s to be allowed in mock Winbox", ip)
	}
}

func TestHandler_PostWhitelist_WithoutWinbox_DoesNotAllowWinbox(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.19"

	form := url.Values{}
	form.Set("ip", ip)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.WinboxAllowed {
		t.Errorf("expected WinboxAllowed=false when winbox param omitted, got true")
	}

	if mockMk.HasWinboxAddress(ip) {
		t.Errorf("did not expect IP %s to be in mock Winbox", ip)
	}
}

func TestHandler_DeleteWhitelist_WithWinbox(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.20"
	mockMk.Entries[ip] = mikrotik.MockEntry{
		ID:      "*1",
		List:    "remote-whitelist",
		Address: ip,
		Comment: "wl|" + ip,
	}
	_ = mockMk.AllowWinbox(context.Background(), ip)

	if !mockMk.HasWinboxAddress(ip) {
		t.Fatalf("expected IP %s to be in mock Winbox initially", ip)
	}

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("winbox", "true")

	req := httptest.NewRequest(http.MethodDelete, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if !resp.WinboxRemoved {
		t.Errorf("expected WinboxRemoved=true, got false")
	}

	if mockMk.HasWinboxAddress(ip) {
		t.Errorf("expected IP %s to be removed from mock Winbox", ip)
	}
}

func TestHandler_PostWhitelist_WinboxError_Returns502(t *testing.T) {
	_, mockMk, router := setupTestServer()

	mockMk.AllowWinboxFn = func(ctx context.Context, ip string) error {
		return errors.New("simulated mikrotik winbox service failure")
	}

	form := url.Values{}
	form.Set("ip", "203.0.113.21")
	form.Set("winbox", "true")

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway on winbox failure, got %d: %s", w.Code, w.Body.String())
	}

	body := strings.TrimSpace(w.Body.String())
	if strings.Contains(body, "simulated mikrotik") {
		t.Errorf("response leaked internal error details: %s", body)
	}
}

func TestHandler_PostWhitelist_AutoDetectHostname_XHostnameHeader(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.30"
	expectedHost := "macbook-air-m2"

	// Request has IP in body, but NO hostname in body. Hostname is in X-Hostname header.
	form := url.Values{}
	form.Set("ip", ip)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Hostname", expectedHost)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Hostname != expectedHost {
		t.Errorf("expected Hostname %q from X-Hostname header, got %q", expectedHost, resp.Hostname)
	}

	entry, ok := mockMk.Entries[ip]
	if !ok {
		t.Fatalf("expected entry for %s", ip)
	}
	if entry.Comment != "wl|"+expectedHost {
		t.Errorf("expected comment 'wl|%s', got %q", expectedHost, entry.Comment)
	}
}

func TestHandler_PostWhitelist_AutoDetectHostname_QueryParam(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.31"
	expectedHost := "thinkpad-t14"

	// Request has hostname in query parameter
	form := url.Values{}
	form.Set("ip", ip)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist?hostname="+expectedHost, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Hostname != expectedHost {
		t.Errorf("expected Hostname %q from query param, got %q", expectedHost, resp.Hostname)
	}

	entry, ok := mockMk.Entries[ip]
	if !ok {
		t.Fatalf("expected entry for %s", ip)
	}
	if entry.Comment != "wl|"+expectedHost {
		t.Errorf("expected comment 'wl|%s', got %q", expectedHost, entry.Comment)
	}
}

func TestHandler_PostWhitelist_AutoDetectHostname_XClientHostnameHeader(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip := "203.0.113.32"
	expectedHost := "dell-xps-15"

	form := url.Values{}
	form.Set("ip", ip)

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Client-Hostname", expectedHost)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp JSONResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Hostname != expectedHost {
		t.Errorf("expected Hostname %q from X-Client-Hostname header, got %q", expectedHost, resp.Hostname)
	}

	entry, ok := mockMk.Entries[ip]
	if !ok {
		t.Fatalf("expected entry for %s", ip)
	}
	if entry.Comment != "wl|"+expectedHost {
		t.Errorf("expected comment 'wl|%s', got %q", expectedHost, entry.Comment)
	}
}
