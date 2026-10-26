package httpserver

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"whitelist-mikrotik/internal/oidc"
)

const (
	oidcStateCookie = "jti_oidc_state"
	oidcPendingTTL  = 10 * time.Minute
	oidcPendingMax  = 10000
)

// pendingAuth holds per-login PKCE/nonce secrets between redirect and callback.
type pendingAuth struct {
	nonce     string
	verifier  string
	expiresAt time.Time
}

type pendingAuthStore struct {
	mu      sync.Mutex
	entries map[string]pendingAuth
}

func newPendingAuthStore() *pendingAuthStore {
	return &pendingAuthStore{entries: make(map[string]pendingAuth)}
}

func (s *pendingAuthStore) put(state string, p pendingAuth) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.entries {
		if v.expiresAt.Before(now) {
			delete(s.entries, k)
		}
	}
	// Bound memory use: this endpoint is reachable without authentication.
	if len(s.entries) >= oidcPendingMax {
		return false
	}
	s.entries[state] = p
	return true
}

// take returns and removes the entry so each state can be used only once.
func (s *pendingAuthStore) take(state string) (pendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.entries[state]
	if !ok {
		return pendingAuth{}, false
	}
	delete(s.entries, state)
	if p.expiresAt.Before(time.Now()) {
		return pendingAuth{}, false
	}
	return p, true
}

// SetOIDC enables Authentik (OIDC) single sign-on. callbackPath must match the
// path of the redirect URL registered in Authentik.
func (h *Handler) SetOIDC(p *oidc.Provider, callbackPath string, disableLocalLogin bool) {
	h.oidc = p
	h.oidcCallbackPath = callbackPath
	h.localLoginDisabled = disableLocalLogin && p != nil
	h.oidcPending = newPendingAuthStore()
}

// authRequired reports whether any authentication mechanism is configured.
func (h *Handler) authRequired() bool {
	return h.oidc != nil || h.authBearerToken != "" || h.adminPass != ""
}

// loginViewData builds the template data for login.html.
func (h *Handler) loginViewData(username, errMsg, csrfToken string) map[string]any {
	if username == "" {
		username = h.adminUser
	}
	return map[string]any{
		"Username":          username,
		"ErrorMessage":      errMsg,
		"CSRFToken":         csrfToken,
		"OIDCEnabled":       h.oidc != nil,
		"LocalLoginEnabled": !h.localLoginDisabled,
	}
}

func (h *Handler) renderLoginError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, h.loginViewData("", msg, h.getOrCreatePreLoginCSRF(w, r)))
}

// HandleOIDCLogin starts the Authentik Authorization Code + PKCE flow.
func (h *Handler) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.NotFound(w, r)
		return
	}
	SetAction(r.Context(), "oidc_login")

	state, err1 := oidc.RandomString(32)
	nonce, err2 := oidc.RandomString(32)
	verifier, err3 := oidc.RandomString(48)
	if err := errors.Join(err1, err2, err3); err != nil {
		h.logger.Error("failed to generate oidc secrets", "error", err)
		http.Error(w, "Gagal memulai login SSO", http.StatusInternalServerError)
		return
	}

	authURL, err := h.oidc.AuthCodeURL(r.Context(), state, nonce, verifier)
	if err != nil {
		h.logger.Error("oidc authorization url failed", "error", err)
		h.renderLoginError(w, r, http.StatusBadGateway, "Server Authentik tidak dapat dihubungi. Silakan coba lagi nanti.")
		return
	}

	if !h.oidcPending.put(state, pendingAuth{nonce: nonce, verifier: verifier, expiresAt: time.Now().Add(oidcPendingTTL)}) {
		h.logger.Warn("oidc pending login store full", "ip", extractSourceIP(r))
		h.renderLoginError(w, r, http.StatusServiceUnavailable, "Terlalu banyak permintaan login. Silakan coba lagi nanti.")
		return
	}

	// Bind the state to this browser to prevent login CSRF.
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   int(oidcPendingTTL / time.Second),
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleOIDCCallback completes the flow: validates state, exchanges the code,
// verifies the id_token and issues a local session cookie.
func (h *Handler) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.NotFound(w, r)
		return
	}
	SetAction(r.Context(), "oidc_callback")
	clientIP := extractSourceIP(r)

	// Always clear the one-shot state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
	})

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		h.logger.Warn("oidc provider returned error", "ip", clientIP, "error", e, "description", q.Get("error_description"))
		h.renderLoginError(w, r, http.StatusUnauthorized, "Login SSO dibatalkan atau ditolak oleh Authentik.")
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	cookie, err := r.Cookie(oidcStateCookie)
	if state == "" || code == "" || err != nil || cookie.Value != state {
		h.logger.Warn("oidc callback state mismatch", "ip", clientIP)
		h.renderLoginError(w, r, http.StatusBadRequest, "Sesi login SSO tidak valid atau kedaluwarsa. Silakan coba lagi.")
		return
	}
	pending, ok := h.oidcPending.take(state)
	if !ok {
		h.logger.Warn("oidc callback unknown or expired state", "ip", clientIP)
		h.renderLoginError(w, r, http.StatusBadRequest, "Sesi login SSO tidak valid atau kedaluwarsa. Silakan coba lagi.")
		return
	}

	claims, idToken, err := h.oidc.Exchange(r.Context(), code, pending.verifier, pending.nonce)
	if err != nil {
		if errors.Is(err, oidc.ErrNotAllowed) {
			h.logger.Warn("oidc user not in allowed groups", "ip", clientIP, "user", claims.DisplayName(), "groups", claims.Groups)
			h.renderLoginError(w, r, http.StatusForbidden, "Akun Anda tidak memiliki akses ke portal ini. Hubungi administrator.")
			return
		}
		h.logger.Error("oidc code exchange failed", "ip", clientIP, "error", err)
		h.renderLoginError(w, r, http.StatusBadGateway, "Verifikasi login SSO gagal. Silakan coba lagi.")
		return
	}

	username := claims.DisplayName()
	session, err := h.sessionStore.CreateOIDCSession(username, clientIP, r.UserAgent(), idToken)
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

	h.logger.Info("user authenticated via authentik", "ip", clientIP, "username", username, "sub", claims.Subject)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
