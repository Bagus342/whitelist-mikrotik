package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"whitelist-mikrotik/internal/auth"
)

type contextKey string

const (
	contextKeyRequestID contextKey = "request_id"
	contextKeyAction    contextKey = "action"
	contextKeyTargetIP  contextKey = "target_ip"
	contextKeySession   contextKey = "session"
)

// GetSession retrieves the authenticated Session from the context if present.
func GetSession(ctx context.Context) *auth.Session {
	if s, ok := ctx.Value(contextKeySession).(*auth.Session); ok {
		return s
	}
	return nil
}

// isHTTPS detects if a request was received over TLS or forwarded as HTTPS by reverse proxy.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Scheme"), "https") {
		return true
	}
	return false
}

// SecurityHeadersMiddleware injects defense-in-depth HTTP security headers into every response.
func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self' https://api.ipify.org;")
			w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

			next.ServeHTTP(w, r)
		})
	}
}

// generateRequestID produces a random hexadecimal request ID string.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000")))
	}
	return hex.EncodeToString(b)
}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// SetAction records the audit action name in the context for logging.
func SetAction(ctx context.Context, action string) {
	if container, ok := ctx.Value(contextKeyAction).(*actionContainer); ok {
		container.setAction(action)
	}
}

// SetTargetIP records the parsed target IP in the context for logging.
func SetTargetIP(ctx context.Context, ip string) {
	if container, ok := ctx.Value(contextKeyTargetIP).(*targetIPContainer); ok {
		container.setIP(ip)
	}
}

type actionContainer struct {
	mu     sync.Mutex
	action string
}

func (a *actionContainer) setAction(action string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.action = action
}

func (a *actionContainer) getAction() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.action
}

type targetIPContainer struct {
	mu sync.Mutex
	ip string
}

func (t *targetIPContainer) setIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ip = ip
}

func (t *targetIPContainer) getIP() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ip
}

// responseRecorder captures the status code and bytes written.
type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseRecorder) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseRecorder) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// extractSourceIP resolves the real client IP from reverse proxy headers.
func extractSourceIP(r *http.Request) string {
	// Try X-Real-IP first
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	// Try X-Forwarded-For (take the first client IP)
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	// Fall back to RemoteAddr
	remote := r.RemoteAddr
	if idx := strings.LastIndex(remote, ":"); idx != -1 {
		return remote[:idx]
	}
	return remote
}

// LoggingMiddleware logs every request in structured JSON using slog.
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			reqID := r.Header.Get("X-Request-ID")
			if reqID == "" {
				reqID = generateRequestID()
			}
			w.Header().Set("X-Request-ID", reqID)

			actionHolder := &actionContainer{action: "rejected"}
			ipHolder := &targetIPContainer{}

			ctx := context.WithValue(r.Context(), contextKeyRequestID, reqID)
			ctx = context.WithValue(ctx, contextKeyAction, actionHolder)
			ctx = context.WithValue(ctx, contextKeyTargetIP, ipHolder)

			rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(rec, r.WithContext(ctx))

			duration := time.Since(start)
			action := actionHolder.getAction()
			targetIP := ipHolder.getIP()
			sourceIP := extractSourceIP(r)
			userAgent := r.UserAgent()

			logAttrs := []any{
				"request_id", reqID,
				"action", action,
				"ip", targetIP,
				"source_ip", sourceIP,
				"user_agent", userAgent,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.statusCode,
				"duration_ms", duration.Milliseconds(),
			}

			if rec.statusCode >= 500 {
				logger.Error("request completed with server error", logAttrs...)
			} else if rec.statusCode >= 400 {
				logger.Warn("request rejected or client error", logAttrs...)
			} else {
				logger.Info("request completed successfully", logAttrs...)
			}
		})
	}
}

// BearerAuthMiddleware verifies the Authorization: Bearer <token> header, auth_token cookie, or token query param.
// If expectedToken is empty, authentication is disabled and requests pass through directly.
// If expectedToken is non-empty, requests must provide a matching Bearer token,
// otherwise a 401 Unauthorized response is returned.
func BearerAuthMiddleware(expectedToken string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		trimmedExpected := strings.TrimSpace(expectedToken)
		if trimmedExpected == "" {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			token := ""
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			} else if strings.HasPrefix(authHeader, "bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(authHeader, "bearer "))
			} else if cookie, err := r.Cookie("auth_token"); err == nil && cookie.Value != "" {
				token = strings.TrimSpace(cookie.Value)
			} else if qToken := r.URL.Query().Get("token"); qToken != "" {
				token = strings.TrimSpace(qToken)
			}

			// Constant-time comparison to prevent timing attacks
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(trimmedExpected)) != 1 {
				reqID := GetRequestID(r.Context())
				SetAction(r.Context(), "unauthorized")
				logger.Warn("unauthorized request: missing or invalid bearer token",
					"request_id", reqID,
					"source_ip", extractSourceIP(r),
					"path", r.URL.Path,
				)

				// For browser requests to root path, show login page
				if r.URL.Path == "/" && strings.Contains(r.Header.Get("Accept"), "text/html") && r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusUnauthorized)
					_ = loginTmpl.Execute(w, map[string]any{
						"Username":  "admin",
						"CSRFToken": "",
					})
					return
				}

				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				writeResponse(w, r, http.StatusUnauthorized, "ERROR unauthorized", JSONResponse{
					Status:    "error",
					Message:   "unauthorized",
					RequestID: reqID,
				})
				return
			}

			// If token was passed via query, set cookie for convenience
			if r.URL.Query().Get("token") != "" {
				http.SetCookie(w, &http.Cookie{
					Name:     "auth_token",
					Value:    token,
					Path:     "/",
					SameSite: http.SameSiteLaxMode,
					MaxAge:   30 * 86400,
				})
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getOrCreatePreLoginCSRF generates or returns a CSRF token for the unauthenticated login form.
func (h *Handler) getOrCreatePreLoginCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie("jti_csrf"); err == nil && len(cookie.Value) == 64 {
		return cookie.Value
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "csrf-fallback-" + generateRequestID()
	}
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     "jti_csrf",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   1800,
	})
	return token
}

// WebAuthMiddleware authenticates web UI requests using session cookies or Bearer tokens.
func (h *Handler) WebAuthMiddleware(authBearerToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectedToken := strings.TrimSpace(authBearerToken)
			expectedPass := strings.TrimSpace(h.adminPass)

			// If no authentication is configured, allow all requests
			if expectedToken == "" && expectedPass == "" {
				next.ServeHTTP(w, r)
				return
			}

			// 1. Check jti_session_id cookie
			if cookie, err := r.Cookie("jti_session_id"); err == nil && cookie.Value != "" {
				if sess, err := h.sessionStore.GetSession(cookie.Value); err == nil && sess != nil {
					ctx := context.WithValue(r.Context(), contextKeySession, sess)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 2. Check Authorization: Bearer <token>, auth_token cookie, or ?token= query parameter
			authHeader := r.Header.Get("Authorization")
			var token string
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			} else if strings.HasPrefix(authHeader, "bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(authHeader, "bearer "))
			} else if cookie, err := r.Cookie("auth_token"); err == nil && cookie.Value != "" {
				token = strings.TrimSpace(cookie.Value)
			} else if qToken := r.URL.Query().Get("token"); qToken != "" {
				token = strings.TrimSpace(qToken)
			}

			if token != "" {
				match := false
				if expectedToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1 {
					match = true
				}
				if !match && expectedPass != "" && auth.VerifyPassword(token, expectedPass) {
					match = true
				}

				if match {
					// Valid token: create or reuse session for seamless browser interaction
					sess, err := h.sessionStore.CreateSession(h.adminUser, extractSourceIP(r), r.UserAgent())
					if err == nil && sess != nil {
						http.SetCookie(w, &http.Cookie{
							Name:     "jti_session_id",
							Value:    sess.ID,
							Path:     "/",
							HttpOnly: true,
							SameSite: http.SameSiteLaxMode,
							Secure:   isHTTPS(r),
							MaxAge:   int(12 * time.Hour / time.Second),
						})
						http.SetCookie(w, &http.Cookie{
							Name:     "auth_token",
							Value:    token,
							Path:     "/",
							SameSite: http.SameSiteLaxMode,
							Secure:   isHTTPS(r),
							MaxAge:   int(12 * time.Hour / time.Second),
						})
						ctx := context.WithValue(r.Context(), contextKeySession, sess)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Not authenticated
			reqID := GetRequestID(r.Context())
			SetAction(r.Context(), "unauthorized")

			// If browser navigating via HTML
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				if r.URL.Path == "/" && r.Method == http.MethodGet {
					csrfToken := h.getOrCreatePreLoginCSRF(w, r)
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusUnauthorized)
					_ = loginTmpl.Execute(w, map[string]any{
						"Username":  h.adminUser,
						"CSRFToken": csrfToken,
					})
					return
				}
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// For API or HTMX AJAX requests, return 401
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeResponse(w, r, http.StatusUnauthorized, "ERROR unauthorized", JSONResponse{
				Status:    "error",
				Message:   "unauthorized",
				RequestID: reqID,
			})
		})
	}
}

// CSRFMiddleware enforces anti-CSRF token verification on state-changing requests.
func (h *Handler) CSRFMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			sess := GetSession(r.Context())
			if sess == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF check for API tokens
			if sess.CSRFToken == "" || sess.CSRFToken == "bearer-auth" {
				next.ServeHTTP(w, r)
				return
			}

			reqCSRF := r.Header.Get("X-CSRF-Token")
			if reqCSRF == "" {
				reqCSRF = r.FormValue("csrf_token")
			}

			if !auth.VerifyCSRF(reqCSRF, sess.CSRFToken) {
				h.logger.Warn("CSRF verification failed",
					"ip", extractSourceIP(r),
					"path", r.URL.Path,
					"user", sess.Username,
				)
				setHXToastHeader(w, "Validasi CSRF gagal. Muat ulang halaman.", "error")
				http.Error(w, "CSRF token tidak valid atau telah kedaluwarsa", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

