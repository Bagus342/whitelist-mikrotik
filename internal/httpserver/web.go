package httpserver

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"whitelist-mikrotik/internal/auth"
	"whitelist-mikrotik/internal/mikrotik"
)

//go:embed web/*
var webFS embed.FS

var (
	indexTmpl   *template.Template
	cardTmpl    *template.Template
	entriesTmpl *template.Template
	loginTmpl   *template.Template
)

func init() {
	var err error
	indexTmpl, err = template.ParseFS(webFS,
		"web/templates/index.html",
		"web/templates/card.html",
		"web/templates/entries.html",
	)
	if err != nil {
		panic(fmt.Sprintf("failed to parse index template: %v", err))
	}

	cardTmpl, err = template.ParseFS(webFS, "web/templates/card.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse card template: %v", err))
	}

	entriesTmpl, err = template.ParseFS(webFS, "web/templates/entries.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse entries template: %v", err))
	}

	loginTmpl, err = template.ParseFS(webFS, "web/templates/login.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse login template: %v", err))
	}
}

// setHXToastHeader adds an HX-Trigger header to trigger toast notifications in the browser.
func setHXToastHeader(w http.ResponseWriter, message, toastType string) {
	payload := map[string]any{
		"toast": map[string]string{
			"message": message,
			"type":    toastType,
		},
	}
	if b, err := json.Marshal(payload); err == nil {
		w.Header().Set("HX-Trigger", string(b))
	}
}

// getStatusOrFallback retrieves client status or returns safe defaults if RouterOS is offline.
func (h *Handler) getStatusOrFallback(r *http.Request, targetIP string) *mikrotik.StatusResult {
	ctx := r.Context()
	status, err := h.mkClient.GetStatus(ctx, targetIP)
	if err != nil {
		h.logger.Warn("mikrotik get status failed, returning fallback telemetry", "ip", targetIP, "error", err)
		status = &mikrotik.StatusResult{
			ClientIP:          targetIP,
			Hostname:          targetIP,
			IsWhitelisted:     false,
			IsInAbuseList:     false,
			WhitelistListName: "remote-whitelist",
			AbuseListName:     "port-forward-abuse",
			IsWinboxAllowed:   false,
			TotalWhitelisted:  0,
			WhitelistTTL:      "8h",
			MikrotikAddress:   "MikroTik (Connecting...)",
			Entries:           []mikrotik.EntryResult{},
		}
	}
	if status.ISP == "" {
		status.ISP = mikrotik.DetectISP(ctx, targetIP)
	}
	if sess := GetSession(ctx); sess != nil {
		status.Username = sess.Username
		status.CSRFToken = sess.CSRFToken
	} else if h.adminUser != "" {
		status.Username = h.adminUser
	}
	return status
}

// HandleIndex renders the main Web UI dashboard.
func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	clientIP := extractSourceIP(r)
	if customIP := strings.TrimSpace(r.URL.Query().Get("ip")); customIP != "" {
		clientIP = customIP
	}

	status := h.getStatusOrFallback(r, clientIP)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, status); err != nil {
		h.logger.Error("failed to render index template", "error", err)
		http.Error(w, "Gagal memuat template halaman", http.StatusInternalServerError)
	}
}

// HandleUIStatus returns the updated Hero Client Card HTML fragment for HTMX polling/refreshes.
func (h *Handler) HandleUIStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := extractSourceIP(r)
	if customIP := strings.TrimSpace(r.URL.Query().Get("ip")); customIP != "" {
		clientIP = customIP
	}

	status := h.getStatusOrFallback(r, clientIP)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := cardTmpl.Execute(w, status); err != nil {
		h.logger.Error("failed to render card template", "error", err)
		http.Error(w, "Gagal memuat status klien", http.StatusInternalServerError)
	}
}

// HandleUIWhitelist handles HTMX POST for adding or extending whitelist.
func (h *Handler) HandleUIWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := GetRequestID(ctx)

	if err := r.ParseForm(); err != nil {
		setHXToastHeader(w, "Format form tidak valid", "error")
		http.Error(w, "Format form tidak valid", http.StatusBadRequest)
		return
	}

	rawIP := strings.TrimSpace(r.FormValue("ip"))
	if rawIP == "" {
		rawIP = extractSourceIP(r)
	}

	addr, err := h.validator.Validate(rawIP)
	if err != nil {
		msg := "IP tidak valid atau tidak diizinkan"
		setHXToastHeader(w, msg, "error")
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	rawHostname := strings.TrimSpace(r.FormValue("hostname"))
	hostname := mikrotik.SanitizeHostname(rawHostname)
	if hostname == "" {
		hostname = mikrotik.ResolveHostname(ctx, addr.String())
	}

	winbox := parseBoolParam(r.Form, "winbox")

	res, err := h.mkClient.Whitelist(ctx, addr.String(), hostname)
	if err != nil {
		h.logger.Error("ui whitelist operation failed", "request_id", reqID, "ip", addr.String(), "error", err)
		setHXToastHeader(w, "Gagal menghubungi router MikroTik", "error")
		http.Error(w, "Gagal menghubungi router MikroTik", http.StatusBadGateway)
		return
	}

	var winboxAllowed bool
	if winbox {
		if err := h.mkClient.AllowWinbox(ctx, addr.String()); err != nil {
			h.logger.Error("ui allow winbox failed", "request_id", reqID, "ip", addr.String(), "error", err)
		} else {
			winboxAllowed = true
		}
	}

	successMsg := fmt.Sprintf("IP %s berhasil didaftarkan ke remote-whitelist", res.IP)
	if res.Action == mikrotik.ActionExtended {
		successMsg = fmt.Sprintf("Masa aktif IP %s berhasil diperpanjang", res.IP)
	}
	if winboxAllowed {
		successMsg += " (Akses Winbox Diizinkan)"
	}

	setHXToastHeader(w, successMsg, "success")
	w.Header().Set("HX-Trigger-After-Swap", `{"refreshEntries": true}`)

	status := h.getStatusOrFallback(r, addr.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = cardTmpl.Execute(w, status)
}

// HandleUIWinbox handles HTMX POST for toggling Winbox port 8291 access for client IP.
func (h *Handler) HandleUIWinbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := GetRequestID(ctx)

	if err := r.ParseForm(); err != nil {
		setHXToastHeader(w, "Format form tidak valid", "error")
		http.Error(w, "Format form tidak valid", http.StatusBadRequest)
		return
	}

	rawIP := strings.TrimSpace(r.FormValue("ip"))
	if rawIP == "" {
		rawIP = extractSourceIP(r)
	}

	addr, err := h.validator.Validate(rawIP)
	if err != nil {
		msg := "IP tidak valid atau tidak diizinkan"
		setHXToastHeader(w, msg, "error")
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	if action == "" {
		action = strings.ToLower(strings.TrimSpace(r.FormValue("action")))
	}

	statusBefore, _ := h.mkClient.GetStatus(ctx, addr.String())
	isAllowed := statusBefore != nil && statusBefore.IsWinboxAllowed

	if action == "remove" || (action == "" && isAllowed) {
		if err := h.mkClient.RemoveWinbox(ctx, addr.String()); err != nil {
			h.logger.Error("ui remove winbox failed", "request_id", reqID, "ip", addr.String(), "error", err)
			setHXToastHeader(w, "Gagal mencabut akses Winbox", "error")
			http.Error(w, "Gagal mencabut akses Winbox", http.StatusBadGateway)
			return
		}
		setHXToastHeader(w, fmt.Sprintf("Akses Winbox untuk IP %s berhasil dicabut", addr.String()), "success")
	} else {
		// Also ensure IP is present in remote-whitelist
		rawHostname := strings.TrimSpace(r.FormValue("hostname"))
		hostname := mikrotik.SanitizeHostname(rawHostname)
		if hostname == "" {
			hostname = mikrotik.ResolveHostname(ctx, addr.String())
		}
		_, _ = h.mkClient.Whitelist(ctx, addr.String(), hostname)

		if err := h.mkClient.AllowWinbox(ctx, addr.String()); err != nil {
			h.logger.Error("ui allow winbox failed", "request_id", reqID, "ip", addr.String(), "error", err)
			setHXToastHeader(w, "Gagal mengizinkan Winbox di MikroTik", "error")
			http.Error(w, "Gagal mengizinkan Winbox", http.StatusBadGateway)
			return
		}
		setHXToastHeader(w, fmt.Sprintf("Akses Winbox (Port 8291) berhasil diizinkan untuk IP %s", addr.String()), "success")
	}

	w.Header().Set("HX-Trigger-After-Swap", `{"refreshEntries": true}`)
	status := h.getStatusOrFallback(r, addr.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = cardTmpl.Execute(w, status)
}

// HandleUIUnwhitelist handles HTMX POST for removing an IP from whitelist.
func (h *Handler) HandleUIUnwhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := GetRequestID(ctx)

	if err := r.ParseForm(); err != nil {
		setHXToastHeader(w, "Format form tidak valid", "error")
		http.Error(w, "Format form tidak valid", http.StatusBadRequest)
		return
	}

	rawIP := strings.TrimSpace(r.FormValue("ip"))
	if rawIP == "" {
		rawIP = extractSourceIP(r)
	}

	addr, err := h.validator.Validate(rawIP)
	if err != nil {
		msg := "IP tidak valid"
		setHXToastHeader(w, msg, "error")
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if err := h.mkClient.Remove(ctx, addr.String()); err != nil {
		h.logger.Error("ui remove operation failed", "request_id", reqID, "ip", addr.String(), "error", err)
		setHXToastHeader(w, "Gagal menghapus IP dari address-list", "error")
		http.Error(w, "Gagal menghapus IP dari address-list", http.StatusBadRequest)
		return
	}

	// Also remove winbox access if present
	_ = h.mkClient.RemoveWinbox(ctx, addr.String())

	setHXToastHeader(w, fmt.Sprintf("IP %s berhasil dihapus dari remote-whitelist", addr.String()), "success")
	w.Header().Set("HX-Trigger-After-Swap", `{"refreshEntries": true}`)

	status := h.getStatusOrFallback(r, addr.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = cardTmpl.Execute(w, status)
}

// HandleUIEntries handles GET (listing entries) and DELETE (deleting a single entry) for the data table.
func (h *Handler) HandleUIEntries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodDelete {
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			http.Error(w, "Parameter ip wajib diisi", http.StatusBadRequest)
			return
		}

		if _, err := netip.ParseAddr(ip); err != nil {
			http.Error(w, "Format IP tidak valid", http.StatusBadRequest)
			return
		}

		if err := h.mkClient.Remove(ctx, ip); err != nil {
			setHXToastHeader(w, "Gagal menghapus IP dari address-list", "error")
			http.Error(w, "Gagal menghapus IP", http.StatusBadRequest)
			return
		}

		_ = h.mkClient.RemoveWinbox(ctx, ip)
		setHXToastHeader(w, fmt.Sprintf("IP %s berhasil dihapus", ip), "success")
		w.WriteHeader(http.StatusOK)
		return
	}

	entries, err := h.mkClient.ListEntries(ctx)
	if err != nil {
		h.logger.Warn("ui list entries error", "error", err)
		entries = []mikrotik.EntryResult{}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = entriesTmpl.Execute(w, map[string]any{
		"Entries": entries,
	})
}

// HandleAPIStatus returns JSON telemetry status.
func (h *Handler) HandleAPIStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := extractSourceIP(r)
	if customIP := strings.TrimSpace(r.URL.Query().Get("ip")); customIP != "" {
		clientIP = customIP
	}

	status := h.getStatusOrFallback(r, clientIP)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

// HandleAPIEntries returns JSON list of firewall address-list entries.
func (h *Handler) HandleAPIEntries(w http.ResponseWriter, r *http.Request) {
	entries, err := h.mkClient.ListEntries(r.Context())
	if err != nil {
		h.logger.Warn("api list entries error", "error", err)
		entries = []mikrotik.EntryResult{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(entries)
}

// HandleStatic serves embedded static assets from web/static/.
func HandleStatic() http.Handler {
	subFS, err := fs.Sub(webFS, "web/static")
	if err != nil {
		panic(fmt.Sprintf("failed to get static subFS: %v", err))
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(subFS)))
}

// HandleLoginPage renders the dedicated login portal.
func (h *Handler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in with valid session, redirect to dashboard
	if cookie, err := r.Cookie("jti_session_id"); err == nil && cookie.Value != "" {
		if sess, err := h.sessionStore.GetSession(cookie.Value); err == nil && sess != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	clientIP := extractSourceIP(r)
	var errMsg string
	isLocked, remaining := h.rateLimiter.CheckLimit(clientIP)
	if isLocked {
		errMsg = fmt.Sprintf("Alamat IP Anda (%s) terkunci karena terlalu banyak percobaan login gagal. Silakan coba lagi dalam %d menit.", clientIP, int(remaining.Minutes())+1)
	}

	csrfToken := h.getOrCreatePreLoginCSRF(w, r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if isLocked {
		w.WriteHeader(http.StatusTooManyRequests)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	_ = loginTmpl.Execute(w, map[string]any{
		"Username":     h.adminUser,
		"ErrorMessage": errMsg,
		"CSRFToken":    csrfToken,
	})
}

// HandleLoginSubmit processes login credentials and issues session cookies.
func (h *Handler) HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	clientIP := extractSourceIP(r)

	// 1. Rate limiter / brute force check
	if isLocked, remaining := h.rateLimiter.CheckLimit(clientIP); isLocked {
		h.logger.Warn("login attempt from locked IP", "ip", clientIP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = loginTmpl.Execute(w, map[string]any{
			"Username":     h.adminUser,
			"ErrorMessage": fmt.Sprintf("Terlalu banyak percobaan gagal. IP Anda terkunci selama %d menit.", int(remaining.Minutes())+1),
			"CSRFToken":    h.getOrCreatePreLoginCSRF(w, r),
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Format form tidak valid", http.StatusBadRequest)
		return
	}

	// 2. Anti-CSRF verification for browser form submission
	reqCSRF := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfCookie, err := r.Cookie("jti_csrf"); err == nil && csrfCookie.Value != "" {
		if !auth.VerifyCSRF(reqCSRF, csrfCookie.Value) {
			h.logger.Warn("login CSRF verification failed", "ip", clientIP)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = loginTmpl.Execute(w, map[string]any{
				"Username":     h.adminUser,
				"ErrorMessage": "Token sesi form kedaluwarsa. Silakan muat ulang halaman.",
				"CSRFToken":    h.getOrCreatePreLoginCSRF(w, r),
			})
			return
		}
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	if password == "" {
		password = strings.TrimSpace(r.FormValue("token"))
	}
	if username == "" {
		username = h.adminUser
	}

	expectedToken := strings.TrimSpace(h.authBearerToken)
	expectedPass := strings.TrimSpace(h.adminPass)

	authenticated := false
	if expectedToken == "" && expectedPass == "" {
		authenticated = true
	} else {
		expectedUser := h.adminUser
		userMatch := false
		if expectedUser == "" || subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) == 1 {
			userMatch = true
		}

		passMatch := false
		if expectedPass != "" && auth.VerifyPassword(password, expectedPass) {
			passMatch = true
		}
		if !passMatch && expectedToken != "" && subtle.ConstantTimeCompare([]byte(password), []byte(expectedToken)) == 1 {
			passMatch = true
		}

		// Dummy work if username didn't match to equalize timing
		if !userMatch {
			_ = auth.VerifyPassword(password, "dummy-salt-hash-constant-timing")
		}

		if userMatch && passMatch {
			authenticated = true
		}
	}

	if !authenticated {
		isLocked, remaining, failures := h.rateLimiter.RecordFailure(clientIP)
		h.logger.Warn("failed login attempt",
			"ip", clientIP,
			"username", username,
			"failures", failures,
			"locked", isLocked,
		)

		status := http.StatusUnauthorized
		var errMsg string
		if isLocked {
			status = http.StatusTooManyRequests
			errMsg = fmt.Sprintf("Terlalu banyak percobaan gagal (%d). Alamat IP Anda terkunci selama %d menit.", failures, int(remaining.Minutes())+1)
		} else {
			errMsg = fmt.Sprintf("Username atau kata sandi salah. Percobaan gagal: %d/5.", failures)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = loginTmpl.Execute(w, map[string]any{
			"Username":     username,
			"ErrorMessage": errMsg,
			"CSRFToken":    h.getOrCreatePreLoginCSRF(w, r),
		})
		return
	}

	// Login succeeded
	h.rateLimiter.RecordSuccess(clientIP)

	loginUser := username
	if loginUser == "" {
		loginUser = h.adminUser
	}

	session, err := h.sessionStore.CreateSession(loginUser, clientIP, r.UserAgent())
	if err != nil {
		h.logger.Error("failed to create session", "error", err)
		http.Error(w, "Gagal membuat sesi", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "jti_session_id",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   int(12 * time.Hour / time.Second),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    password,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   int(12 * time.Hour / time.Second),
	})

	h.logger.Info("user authenticated successfully", "ip", clientIP, "username", loginUser)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleLogout revokes the user's session and clears cookies.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("jti_session_id"); err == nil && cookie.Value != "" {
		h.sessionStore.RevokeSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "jti_session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
