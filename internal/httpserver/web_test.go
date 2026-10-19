package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"whitelist-mikrotik/internal/mikrotik"
)

func TestWebUI_StaticFiles(t *testing.T) {
	_, _, router := setupTestServer()

	// 1. style.css
	reqCSS := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	wCSS := httptest.NewRecorder()
	router.ServeHTTP(wCSS, reqCSS)
	if wCSS.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /static/css/style.css, got %d", wCSS.Code)
	}
	if !strings.Contains(wCSS.Body.String(), "PT JAGAT TEKNOLOGI INDONESIA") {
		t.Errorf("expected style.css to contain PT JAGAT TEKNOLOGI INDONESIA header")
	}

	// 2. htmx.min.js
	reqHTMX := httptest.NewRequest(http.MethodGet, "/static/js/htmx.min.js", nil)
	wHTMX := httptest.NewRecorder()
	router.ServeHTTP(wHTMX, reqHTMX)
	if wHTMX.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /static/js/htmx.min.js, got %d", wHTMX.Code)
	}
	if !strings.Contains(wHTMX.Body.String(), "htmx") {
		t.Errorf("expected htmx.min.js to contain htmx definition")
	}

	// 3. app.js
	reqApp := httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
	wApp := httptest.NewRecorder()
	router.ServeHTTP(wApp, reqApp)
	if wApp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /static/js/app.js, got %d", wApp.Code)
	}
	if !strings.Contains(wApp.Body.String(), "PT JAGAT TEKNOLOGI INDONESIA") {
		t.Errorf("expected app.js to contain brand header")
	}
}

func TestWebUI_IndexDashboard(t *testing.T) {
	_, _, router := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.88:54321"
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "JTI Whitelist Portal") {
		t.Errorf("expected body to contain 'JTI Whitelist Portal'")
	}
	if !strings.Contains(body, "203.0.113.88") {
		t.Errorf("expected body to contain detected IP '203.0.113.88'")
	}
	if !strings.Contains(body, "hero-client-card") {
		t.Errorf("expected body to contain 'hero-client-card'")
	}
	if !strings.Contains(body, "htmx.min.js") {
		t.Errorf("expected body to include htmx script")
	}
	if !strings.Contains(body, "badge-provider") {
		t.Errorf("expected body to include badge-provider")
	}
	if !strings.Contains(body, "client-provider-text") {
		t.Errorf("expected body to include client-provider-text")
	}
	if strings.Contains(body, "client-hostname-text") {
		t.Errorf("expected hostname badge to be removed from UI")
	}
	if !strings.Contains(body, "Whitelist Winbox") {
		t.Errorf("expected body to include Whitelist Winbox card")
	}
	if strings.Contains(body, "Router Terhubung") {
		t.Errorf("expected 'Router Terhubung' to be removed from navbar")
	}
	if strings.Contains(body, "user-badge") {
		t.Errorf("expected user badge to be removed from navbar")
	}
	if !strings.Contains(body, "Keluar") {
		t.Errorf("expected logout button 'Keluar' to be present")
	}
	if !strings.Contains(body, "switching-modal-overlay") {
		t.Errorf("expected body to include switching overlay modal")
	}
	if strings.Contains(body, "address-list-status-card") {
		t.Errorf("expected body to NOT include address-list-status-card")
	}
	if strings.Contains(body, "Status Firewall Address-List") {
		t.Errorf("expected body to NOT include Status Firewall Address-List")
	}
	if !strings.Contains(body, "port-abuse-card") {
		t.Errorf("expected body to include port-abuse-card")
	}
	if !strings.Contains(body, "port-forward-abuse") {
		t.Errorf("expected body to include port-forward-abuse list name")
	}
	if !strings.Contains(body, "CLEAN IP ADDRESS") {
		t.Errorf("expected abuse status to show 'CLEAN IP ADDRESS' for clean IP")
	}
	if !strings.Contains(body, "IP Bersih") {
		t.Errorf("expected abuse status to show 'IP Bersih' for clean IP")
	}
	if !strings.Contains(body, "Jaringan anda bersih dari aktifitas mencurigakan") {
		t.Errorf("expected clean subtitle in abuse card")
	}
}

func TestWebUI_UIStatus(t *testing.T) {
	_, mockMk, router := setupTestServer()

	// Pre-whitelist an IP
	testIP := "203.0.113.99"
	_, _ = mockMk.Whitelist(context.Background(), testIP, "test-host")

	req := httptest.NewRequest(http.MethodGet, "/ui/status?ip="+testIP, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/status, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, testIP) {
		t.Errorf("expected body to contain %s", testIP)
	}
	if !strings.Contains(body, "AKTIF (WHITELISTED)") {
		t.Errorf("expected body to show 'AKTIF (WHITELISTED)', got: %s", body)
	}
	if !strings.Contains(body, "Perpanjang Whitelist") {
		t.Errorf("expected body to have 'Perpanjang Whitelist' button")
	}
	if strings.Contains(body, "address-list-status-card") {
		t.Errorf("expected body to NOT include address-list-status-card")
	}
	if !strings.Contains(body, "port-abuse-card") {
		t.Errorf("expected body to include port-abuse-card")
	}
}

func TestWebUI_AddressListStatusCard_Abuse(t *testing.T) {
	_, mockMk, router := setupTestServer()

	abuseIP := "203.0.113.77"
	mockMk.AddAbuseEntry(abuseIP)

	req := httptest.NewRequest(http.MethodGet, "/ui/status?ip="+abuseIP, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/status for abuse IP, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if strings.Contains(body, "address-list-status-card") {
		t.Errorf("expected body to NOT contain address-list-status-card")
	}
	if !strings.Contains(body, "port-abuse-card") {
		t.Errorf("expected body to contain port-abuse-card")
	}
	if !strings.Contains(body, "port-forward-abuse") {
		t.Errorf("expected body to contain port-forward-abuse")
	}
	if !strings.Contains(body, "ABUSE DETECTION") {
		t.Errorf("expected body to show 'ABUSE DETECTION', got: %s", body)
	}
	if !strings.Contains(body, "IP Diblokir") {
		t.Errorf("expected body to show 'IP Diblokir', got: %s", body)
	}
	if !strings.Contains(body, "Jaringan anda terdeteksi aktifitas mencurigakan") {
		t.Errorf("expected abuse subtitle in abuse card")
	}
}

func TestWebUI_UIWhitelist_And_Unwhitelist(t *testing.T) {
	_, mockMk, router := setupTestServer()

	targetIP := "203.0.113.120"

	// 1. POST /ui/whitelist with winbox=true
	form := url.Values{}
	form.Set("ip", targetIP)
	form.Set("hostname", "engineer-mac")
	form.Set("winbox", "true")

	req := httptest.NewRequest(http.MethodPost, "/ui/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/whitelist, got %d: %s", w.Code, w.Body.String())
	}

	// Verify toast trigger header
	hxTrigger := w.Header().Get("HX-Trigger")
	if !strings.Contains(hxTrigger, "toast") || !strings.Contains(hxTrigger, targetIP) {
		t.Errorf("expected HX-Trigger header with toast, got %s", hxTrigger)
	}

	// Verify mock state
	if _, whitelisted := mockMk.Entries[targetIP]; !whitelisted {
		t.Errorf("expected IP %s to be in mock Entries", targetIP)
	}
	if !mockMk.HasWinboxAddress(targetIP) {
		t.Errorf("expected IP %s to be allowed in Winbox", targetIP)
	}

	// Response card should reflect whitelisted status
	cardBody := w.Body.String()
	if !strings.Contains(cardBody, "AKTIF (WHITELISTED)") {
		t.Errorf("expected card to show AKTIF (WHITELISTED)")
	}

	// 2. POST /ui/unwhitelist
	unwlForm := url.Values{}
	unwlForm.Set("ip", targetIP)
	unwlReq := httptest.NewRequest(http.MethodPost, "/ui/unwhitelist", strings.NewReader(unwlForm.Encode()))
	unwlReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unwlW := httptest.NewRecorder()

	router.ServeHTTP(unwlW, unwlReq)

	if unwlW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/unwhitelist, got %d: %s", unwlW.Code, unwlW.Body.String())
	}

	if _, stillWhitelisted := mockMk.Entries[targetIP]; stillWhitelisted {
		t.Errorf("expected IP %s to be removed from mock Entries", targetIP)
	}
	if mockMk.HasWinboxAddress(targetIP) {
		t.Errorf("expected IP %s to be removed from Winbox", targetIP)
	}
}

func TestWebUI_UIWinbox(t *testing.T) {
	_, mockMk, router := setupTestServer()

	targetIP := "203.0.113.130"

	// 1. POST /ui/winbox to allow Winbox
	form := url.Values{}
	form.Set("ip", targetIP)

	req := httptest.NewRequest(http.MethodPost, "/ui/winbox", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/winbox, got %d: %s", w.Code, w.Body.String())
	}

	if !mockMk.HasWinboxAddress(targetIP) {
		t.Errorf("expected IP %s to be allowed in Winbox", targetIP)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Winbox Diizinkan") {
		t.Errorf("expected body to contain 'Winbox Diizinkan', got: %s", body)
	}
	if !strings.Contains(body, "Cabut Winbox") {
		t.Errorf("expected body to have 'Cabut Winbox' button")
	}

	// 2. POST /ui/winbox again to toggle/remove Winbox
	unreq := httptest.NewRequest(http.MethodPost, "/ui/winbox", strings.NewReader(form.Encode()))
	unreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unw := httptest.NewRecorder()

	router.ServeHTTP(unw, unreq)

	if unw.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/winbox remove, got %d: %s", unw.Code, unw.Body.String())
	}

	if mockMk.HasWinboxAddress(targetIP) {
		t.Errorf("expected IP %s to be removed from Winbox", targetIP)
	}

	unbody := unw.Body.String()
	if !strings.Contains(unbody, "Whitelist Winbox") {
		t.Errorf("expected body to contain 'Whitelist Winbox'")
	}
}

func TestWebUI_UIEntries_ListAndDelete(t *testing.T) {
	_, mockMk, router := setupTestServer()

	ip1 := "203.0.113.11"
	ip2 := "203.0.113.22"
	_, _ = mockMk.Whitelist(context.Background(), ip1, "laptop-1")
	_, _ = mockMk.Whitelist(context.Background(), ip2, "laptop-2")

	// 1. GET /ui/entries
	req := httptest.NewRequest(http.MethodGet, "/ui/entries", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /ui/entries, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, ip1) || !strings.Contains(body, ip2) {
		t.Errorf("expected entries body to contain %s and %s, got: %s", ip1, ip2, body)
	}

	// 2. DELETE /ui/entries?ip=...
	delReq := httptest.NewRequest(http.MethodDelete, "/ui/entries?ip="+ip1, nil)
	delW := httptest.NewRecorder()
	router.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DELETE /ui/entries, got %d: %s", delW.Code, delW.Body.String())
	}
	if _, exists := mockMk.Entries[ip1]; exists {
		t.Errorf("expected %s to be deleted from entries", ip1)
	}
}

func TestWebUI_APIStatusAndEntries(t *testing.T) {
	_, mockMk, router := setupTestServer()

	testIP := "203.0.113.33"
	_, _ = mockMk.Whitelist(context.Background(), testIP, "api-laptop")

	// 1. GET /api/status
	req := httptest.NewRequest(http.MethodGet, "/api/status?ip="+testIP, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/status, got %d", w.Code)
	}

	var status mikrotik.StatusResult
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse /api/status JSON: %v", err)
	}
	if status.ClientIP != testIP || !status.IsWhitelisted {
		t.Errorf("unexpected status result: %+v", status)
	}
	if status.ISP == "" {
		t.Errorf("expected status.ISP to be populated, got empty")
	}

	// 2. GET /api/entries
	reqEntries := httptest.NewRequest(http.MethodGet, "/api/entries", nil)
	wEntries := httptest.NewRecorder()
	router.ServeHTTP(wEntries, reqEntries)

	if wEntries.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/entries, got %d", wEntries.Code)
	}

	var entries []mikrotik.EntryResult
	if err := json.Unmarshal(wEntries.Body.Bytes(), &entries); err != nil {
		t.Fatalf("failed to parse /api/entries JSON: %v", err)
	}
	if len(entries) == 0 {
		t.Errorf("expected at least 1 entry in /api/entries")
	}
}

func TestWebUI_BearerAuth_CookieAndQueryParam(t *testing.T) {
	token := "secure-portal-token"
	_, _, router := setupAuthenticatedTestServer(token)

	// 1. Access root without token via HTML browser -> returns 401 with login HTML page
	reqHTML := httptest.NewRequest(http.MethodGet, "/", nil)
	reqHTML.Header.Set("Accept", "text/html")
	wHTML := httptest.NewRecorder()
	router.ServeHTTP(wHTML, reqHTML)

	if wHTML.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", wHTML.Code)
	}
	if !strings.Contains(wHTML.Body.String(), "Bearer Auth Token") {
		t.Errorf("expected login page with 'Bearer Auth Token'")
	}

	// 2. Access with valid query param ?token=... -> returns 200 and sets auth_token cookie
	reqQuery := httptest.NewRequest(http.MethodGet, "/?token="+token, nil)
	reqQuery.Header.Set("Accept", "text/html")
	wQuery := httptest.NewRecorder()
	router.ServeHTTP(wQuery, reqQuery)

	if wQuery.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with ?token=..., got %d", wQuery.Code)
	}
	cookies := wQuery.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "auth_token" {
			authCookie = c
			break
		}
	}
	if authCookie == nil || authCookie.Value != token {
		t.Errorf("expected auth_token cookie to be set with token value")
	}

	// 3. Access with valid auth_token cookie -> returns 200 OK
	reqCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCookie.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	wCookie := httptest.NewRecorder()
	router.ServeHTTP(wCookie, reqCookie)

	if wCookie.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with auth_token cookie, got %d", wCookie.Code)
	}

	// 4. POST /ui/login sets cookie and redirects
	loginForm := url.Values{}
	loginForm.Set("token", token)
	reqLogin := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(loginForm.Encode()))
	reqLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wLogin := httptest.NewRecorder()
	router.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 See Other redirect on /ui/login, got %d", wLogin.Code)
	}
}

func TestWebUI_LoginPage_Rendering(t *testing.T) {
	token := "secure-test-token"
	_, _, router := setupAuthenticatedTestServer(token)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET /login, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "PT Jagat Teknologi Indonesia") {
		t.Errorf("expected login page to contain brand name")
	}
	if !strings.Contains(body, "Username Administrator") {
		t.Errorf("expected login page to contain username field")
	}
	if !strings.Contains(body, "Kata Sandi / Bearer Auth Token") {
		t.Errorf("expected login page to contain password field")
	}
	if !strings.Contains(body, "csrf_token") {
		t.Errorf("expected login page to contain csrf_token hidden field")
	}
}

func TestWebUI_Login_Success_SetsSecureHttpOnlySessionCookie(t *testing.T) {
	token := "correct-admin-password"
	handler, _, router := setupAuthenticatedTestServer(token)
	handler.SetAuth("admin", token)

	loginForm := url.Values{}
	loginForm.Set("username", "admin")
	loginForm.Set("password", token)

	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(loginForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 See Other on successful login, got %d: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("expected redirect to /, got %s", loc)
	}

	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "jti_session_id" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatalf("expected jti_session_id cookie to be set")
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("expected jti_session_id to be HttpOnly")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.Path != "/" {
		t.Errorf("expected Path=/, got %s", sessionCookie.Path)
	}

	// Verify accessing / with the session cookie succeeds and renders user dashboard
	reqDash := httptest.NewRequest(http.MethodGet, "/", nil)
	reqDash.AddCookie(sessionCookie)
	reqDash.Header.Set("Accept", "text/html")
	wDash := httptest.NewRecorder()
	router.ServeHTTP(wDash, reqDash)

	if wDash.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on / with session cookie, got %d: %s", wDash.Code, wDash.Body.String())
	}
	if !strings.Contains(wDash.Body.String(), "Keluar") {
		t.Errorf("expected dashboard to contain logout button 'Keluar'")
	}
	if !strings.Contains(wDash.Body.String(), "hero-client-card") {
		t.Errorf("expected dashboard to contain hero card")
	}
}

func TestWebUI_Login_BruteForceLockout(t *testing.T) {
	token := "super-secure-token"
	handler, _, router := setupAuthenticatedTestServer(token)
	handler.SetAuth("admin", token)

	attackerIP := "198.51.100.77"

	// Send 4 failed login attempts -> all should return 401 Unauthorized
	for i := 1; i <= 4; i++ {
		form := url.Values{}
		form.Set("username", "admin")
		form.Set("password", fmt.Sprintf("wrong-pass-%d", i))

		req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = attackerIP + ":12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 Unauthorized, got %d", i, w.Code)
		}
		if !strings.Contains(w.Body.String(), "salah") {
			t.Errorf("attempt %d: expected error message with 'salah'", i)
		}
	}

	// 5th attempt -> triggers brute force lockout (429 Too Many Requests)
	form5 := url.Values{}
	form5.Set("username", "admin")
	form5.Set("password", "wrong-pass-5")

	req5 := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form5.Encode()))
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req5.RemoteAddr = attackerIP + ":12345"
	w5 := httptest.NewRecorder()
	router.ServeHTTP(w5, req5)

	if w5.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 5: expected 429 Too Many Requests, got %d", w5.Code)
	}
	if !strings.Contains(w5.Body.String(), "terkunci") {
		t.Errorf("attempt 5: expected message containing 'terkunci', got: %s", w5.Body.String())
	}

	// Further attempt, even with the CORRECT password, should be blocked by rate limiter!
	reqBlocked := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(url.Values{
		"username": {"admin"},
		"password": {token},
	}.Encode()))
	reqBlocked.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBlocked.RemoteAddr = attackerIP + ":12345"
	wBlocked := httptest.NewRecorder()
	router.ServeHTTP(wBlocked, reqBlocked)

	if wBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests even with correct password during lockout, got %d", wBlocked.Code)
	}

	// GET /login from locked IP should show lockout error banner
	reqPage := httptest.NewRequest(http.MethodGet, "/login", nil)
	reqPage.RemoteAddr = attackerIP + ":12345"
	wPage := httptest.NewRecorder()
	router.ServeHTTP(wPage, reqPage)

	if wPage.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on GET /login from locked IP, got %d", wPage.Code)
	}
	if !strings.Contains(wPage.Body.String(), "terkunci") {
		t.Errorf("expected login page to indicate lockout")
	}
}

func TestWebUI_AntiCSRF_Protection(t *testing.T) {
	token := "secure-token-123"
	handler, mockMk, router := setupAuthenticatedTestServer(token)
	handler.SetAuth("admin", token)

	// Create valid user session
	sess, err := handler.GetSessionStore().CreateSession("admin", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sessionCookie := &http.Cookie{
		Name:  "jti_session_id",
		Value: sess.ID,
	}

	targetIP := "203.0.113.66"

	// 1. POST /ui/whitelist WITHOUT CSRF token -> Rejected with 403 Forbidden
	formNoCSRF := url.Values{}
	formNoCSRF.Set("ip", targetIP)
	formNoCSRF.Set("hostname", "test-device")

	reqNoCSRF := httptest.NewRequest(http.MethodPost, "/ui/whitelist", strings.NewReader(formNoCSRF.Encode()))
	reqNoCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqNoCSRF.AddCookie(sessionCookie)
	wNoCSRF := httptest.NewRecorder()
	router.ServeHTTP(wNoCSRF, reqNoCSRF)

	if wNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden without CSRF token, got %d: %s", wNoCSRF.Code, wNoCSRF.Body.String())
	}
	if _, exists := mockMk.Entries[targetIP]; exists {
		t.Errorf("target IP should NOT have been whitelisted without CSRF token")
	}

	// 2. POST /ui/whitelist with WRONG CSRF token -> Rejected with 403 Forbidden
	reqBadCSRF := httptest.NewRequest(http.MethodPost, "/ui/whitelist", strings.NewReader(formNoCSRF.Encode()))
	reqBadCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBadCSRF.Header.Set("X-CSRF-Token", "invalid-fake-token")
	reqBadCSRF.AddCookie(sessionCookie)
	wBadCSRF := httptest.NewRecorder()
	router.ServeHTTP(wBadCSRF, reqBadCSRF)

	if wBadCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden with invalid CSRF token, got %d", wBadCSRF.Code)
	}

	// 3. POST /ui/whitelist with VALID X-CSRF-Token -> Allowed (200 OK)
	reqValidCSRF := httptest.NewRequest(http.MethodPost, "/ui/whitelist", strings.NewReader(formNoCSRF.Encode()))
	reqValidCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqValidCSRF.Header.Set("X-CSRF-Token", sess.CSRFToken)
	reqValidCSRF.AddCookie(sessionCookie)
	wValidCSRF := httptest.NewRecorder()
	router.ServeHTTP(wValidCSRF, reqValidCSRF)

	if wValidCSRF.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid CSRF token, got %d: %s", wValidCSRF.Code, wValidCSRF.Body.String())
	}
	if _, exists := mockMk.Entries[targetIP]; !exists {
		t.Errorf("target IP should be whitelisted with valid CSRF token")
	}
}

func TestWebUI_Logout_RevokesSession(t *testing.T) {
	token := "secure-token-logout"
	handler, _, router := setupAuthenticatedTestServer(token)
	handler.SetAuth("admin", token)

	sess, err := handler.GetSessionStore().CreateSession("admin", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sessionCookie := &http.Cookie{
		Name:  "jti_session_id",
		Value: sess.ID,
	}

	// POST /ui/logout
	reqLogout := httptest.NewRequest(http.MethodPost, "/ui/logout", nil)
	reqLogout.AddCookie(sessionCookie)
	wLogout := httptest.NewRecorder()
	router.ServeHTTP(wLogout, reqLogout)

	if wLogout.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 See Other on logout, got %d", wLogout.Code)
	}
	if loc := wLogout.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}

	// Verify session in store was revoked
	if _, err := handler.GetSessionStore().GetSession(sess.ID); err == nil {
		t.Errorf("expected session to be revoked in store")
	}

	// Subsequent request with the revoked cookie should be unauthorized
	reqAfter := httptest.NewRequest(http.MethodGet, "/ui/status", nil)
	reqAfter.AddCookie(sessionCookie)
	wAfter := httptest.NewRecorder()
	router.ServeHTTP(wAfter, reqAfter)

	if wAfter.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after logout, got %d", wAfter.Code)
	}
}

func TestWebUI_SecurityHeaders(t *testing.T) {
	_, _, router := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	h := w.Header()
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing or incorrect X-Content-Type-Options")
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing or incorrect X-Frame-Options")
	}
	if h.Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("missing or incorrect Referrer-Policy")
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("missing or incorrect Content-Security-Policy")
	}
}
