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
)

type contextKey string

const (
	contextKeyRequestID contextKey = "request_id"
	contextKeyAction    contextKey = "action"
	contextKeyTargetIP  contextKey = "target_ip"
)

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

// BearerAuthMiddleware verifies the Authorization: Bearer <token> header.
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

				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				writeResponse(w, r, http.StatusUnauthorized, "ERROR unauthorized", JSONResponse{
					Status:    "error",
					Message:   "unauthorized",
					RequestID: reqID,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
