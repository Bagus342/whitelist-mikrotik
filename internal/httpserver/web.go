package httpserver

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/netip"
	"strings"
	"time"

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

// HandleLoginPage renders the login portal with the Authentik SSO button.
func (h *Handler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("jti_session_id"); err == nil && cookie.Value != "" {
		if sess, err := h.sessionStore.GetSession(cookie.Value); err == nil && sess != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, h.loginViewData(""))
}

// HandleLogout revokes the local session and ends the Authentik session
// (RP-initiated logout) when the provider supports it.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	redirectTo := "/login"
	if cookie, err := r.Cookie("jti_session_id"); err == nil && cookie.Value != "" {
		if sess, err := h.sessionStore.GetSession(cookie.Value); err == nil && h.oidc != nil {
			if u := h.oidc.EndSessionURL(r.Context(), sess.IDToken); u != "" {
				redirectTo = u
			}
		}
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

	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}
