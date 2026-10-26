package httpserver

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"whitelist-mikrotik/internal/ipcheck"
	"whitelist-mikrotik/internal/mikrotik"
	"whitelist-mikrotik/internal/oidc"
)

// fakeIdP is a minimal Authentik-like OIDC provider for tests.
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string

	mu        sync.Mutex
	nonce     string
	challenge string
	groups    []string
	badNonce  bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, clientID: "wl-client", groups: []string{"network-admins"}}
	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	issuer := idp.srv.URL + "/application/o/wl/"

	mux.HandleFunc("/application/o/wl/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": idp.srv.URL + "/application/o/authorize/",
			"token_endpoint":         idp.srv.URL + "/application/o/token/",
			"jwks_uri":               idp.srv.URL + "/application/o/wl/jwks/",
			"end_session_endpoint":   idp.srv.URL + "/application/o/wl/end-session/",
		})
	})
	mux.HandleFunc("/application/o/wl/jwks/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/application/o/token/", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		defer idp.mu.Unlock()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if r.FormValue("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge ||
			r.FormValue("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		nonce := idp.nonce
		if idp.badNonce {
			nonce = "forged"
		}
		claims := map[string]any{
			"iss": issuer, "aud": idp.clientID, "sub": "user-123",
			"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
			"nonce": nonce, "preferred_username": "budi", "email": "budi@example.com",
			"groups": idp.groups,
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idp.sign(t, claims), "token_type": "Bearer"})
	})
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) issuer() string { return idp.srv.URL + "/application/o/wl/" }

func (idp *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func setupOIDCServer(t *testing.T, idp *fakeIdP, allowedGroups []string) (*Handler, http.Handler) {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	validator := ipcheck.NewValidator(false, []netip.Prefix{netip.MustParsePrefix("203.0.113.100/32")})
	handler := NewHandler(validator, mikrotik.NewMockClient(), logger)
	handler.SetOIDC(oidc.NewProvider(oidc.Config{
		IssuerURL:     idp.issuer(),
		ClientID:      idp.clientID,
		ClientSecret:  "s3cret",
		RedirectURL:   "https://wl.example.com/auth/callback",
		AllowedGroups: allowedGroups,
		PostLogoutURL: "https://wl.example.com/login",
	}), "/auth/callback")
	return handler, SetupRouter(handler, "", logger)
}

// runOIDCLogin drives /auth/login → IdP → /auth/callback and returns the callback response.
func runOIDCLogin(t *testing.T, idp *fakeIdP, router http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 from /auth/login, got %d: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), idp.srv.URL+"/application/o/authorize/") {
		t.Fatalf("unexpected authorize redirect: %s", w.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != idp.clientID || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorize URL missing PKCE/client/scope params: %s", loc)
	}
	idp.mu.Lock()
	idp.nonce = q.Get("nonce")
	idp.challenge = q.Get("code_challenge")
	idp.mu.Unlock()

	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == oidcStateCookie {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value != q.Get("state") {
		t.Fatalf("state cookie missing or mismatched")
	}

	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state="+url.QueryEscape(q.Get("state")), nil)
	cb.AddCookie(stateCookie)
	cw := httptest.NewRecorder()
	router.ServeHTTP(cw, cb)
	return cw
}

func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "jti_session_id" && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestOIDC_FullLoginAndLogout(t *testing.T) {
	idp := newFakeIdP(t)
	handler, router := setupOIDCServer(t, idp, []string{"network-admins"})

	cw := runOIDCLogin(t, idp, router)
	if cw.Code != http.StatusSeeOther || cw.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to / after callback, got %d %s: %s", cw.Code, cw.Header().Get("Location"), cw.Body.String())
	}
	sc := sessionCookie(cw)
	if sc == nil {
		t.Fatal("expected session cookie after successful SSO login")
	}
	sess, err := handler.GetSessionStore().GetSession(sc.Value)
	if err != nil || sess.Username != "budi" || sess.IDToken == "" {
		t.Fatalf("unexpected session: %+v err=%v", sess, err)
	}

	// Dashboard is reachable with the SSO session.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.88:54321"
	req.AddCookie(sc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on dashboard with SSO session, got %d", w.Code)
	}

	// Logout redirects to Authentik end-session with id_token_hint.
	lreq := httptest.NewRequest(http.MethodPost, "/ui/logout", nil)
	lreq.AddCookie(sc)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, lreq)
	loc := lw.Header().Get("Location")
	if !strings.HasPrefix(loc, idp.srv.URL+"/application/o/wl/end-session/") || !strings.Contains(loc, "id_token_hint=") {
		t.Fatalf("expected end-session redirect, got %q", loc)
	}
	if _, err := handler.GetSessionStore().GetSession(sc.Value); err == nil {
		t.Fatal("session should be revoked after logout")
	}
}

func TestOIDC_RejectsUserOutsideAllowedGroups(t *testing.T) {
	idp := newFakeIdP(t)
	idp.groups = []string{"interns"}
	_, router := setupOIDCServer(t, idp, []string{"network-admins"})

	cw := runOIDCLogin(t, idp, router)
	if cw.Code != http.StatusForbidden || sessionCookie(cw) != nil {
		t.Fatalf("expected 403 without session, got %d", cw.Code)
	}
}

func TestOIDC_RejectsNonceMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	idp.badNonce = true
	_, router := setupOIDCServer(t, idp, nil)

	cw := runOIDCLogin(t, idp, router)
	if cw.Code != http.StatusBadGateway || sessionCookie(cw) != nil {
		t.Fatalf("expected 502 without session on nonce mismatch, got %d", cw.Code)
	}
}

func TestOIDC_RejectsStateMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	_, router := setupOIDCServer(t, idp, nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state=attacker", nil)
	cb.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "victim"})
	cw := httptest.NewRecorder()
	router.ServeHTTP(cw, cb)
	if cw.Code != http.StatusBadRequest || sessionCookie(cw) != nil {
		t.Fatalf("expected 400 on state mismatch, got %d", cw.Code)
	}
}
