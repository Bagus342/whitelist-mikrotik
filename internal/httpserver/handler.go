package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"whitelist-mikrotik/internal/ipcheck"
	"whitelist-mikrotik/internal/mikrotik"
)

// Handler contains dependencies for handling HTTP requests.
type Handler struct {
	validator *ipcheck.Validator
	mkClient  mikrotik.Client
	logger    *slog.Logger
}

// NewHandler constructs a new Handler.
func NewHandler(v *ipcheck.Validator, mk mikrotik.Client, l *slog.Logger) *Handler {
	return &Handler{
		validator: v,
		mkClient:  mk,
		logger:    l,
	}
}

// JSONResponse represents a generic JSON envelope for responses.
type JSONResponse struct {
	Status           string `json:"status"`
	IP               string `json:"ip,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	Expires          string `json:"expires,omitempty"`
	Action           string `json:"action,omitempty"`
	Message          string `json:"message,omitempty"`
	RequestID        string `json:"req,omitempty"`
	RemovedFromAbuse bool   `json:"removed_from_abuse,omitempty"`
	WinboxAllowed    bool   `json:"winbox_allowed,omitempty"`
	WinboxRemoved    bool   `json:"winbox_removed,omitempty"`
}

// writeResponse sends either text/plain (default) or application/json based on the Accept header.
func writeResponse(w http.ResponseWriter, r *http.Request, statusCode int, textMsg string, jsonResp JSONResponse) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(jsonResp)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintln(w, textMsg)
}

// parseBoolParam checks if a form key is present as a flag or true boolean.
func parseBoolParam(values url.Values, key string) bool {
	if !values.Has(key) {
		return false
	}
	val := strings.ToLower(strings.TrimSpace(values.Get(key)))
	// Empty string corresponds to flag parameter e.g. "ip=...&winbox"
	return val == "" || val == "true" || val == "1" || val == "yes" || val == "on"
}

// parseJSONBool handles boolean, string, or numeric JSON representation of booleans.
func parseJSONBool(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		s := strings.ToLower(strings.TrimSpace(val))
		return s == "true" || s == "1" || s == "yes" || s == "on" || s == ""
	case float64:
		return val != 0
	default:
		return false
	}
}

// parseIPForm reads and validates the "ip" field from the request body,
// extracts or resolves the target hostname, and checks for the "winbox" parameter.
// Enforces a 1 KB maximum body size and supports application/x-www-form-urlencoded and JSON.
func (h *Handler) parseIPForm(w http.ResponseWriter, r *http.Request) (netip.Addr, string, bool, error) {
	reqID := GetRequestID(r.Context())

	// Enforce 1 KB maximum body size
	limitedReader := http.MaxBytesReader(w, r.Body, 1024)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.logger.Warn("request body exceeded 1 KB limit", "request_id", reqID)
			writeResponse(w, r, http.StatusBadRequest, "ERROR body terlalu besar (maksimal 1 KB)", JSONResponse{
				Status:    "error",
				Message:   "body terlalu besar (maksimal 1 KB)",
				RequestID: reqID,
			})
			return netip.Addr{}, "", false, err
		}

		writeResponse(w, r, http.StatusBadRequest, "ERROR gagal membaca body", JSONResponse{
			Status:    "error",
			Message:   "gagal membaca body",
			RequestID: reqID,
		})
		return netip.Addr{}, "", false, err
	}

	trimmedBody := strings.TrimSpace(string(bodyBytes))
	var rawIP, rawHostname string
	var winbox bool

	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json") ||
		strings.HasPrefix(trimmedBody, "{")

	if isJSON {
		var payload struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			Host     string `json:"host"`
			Winbox   any    `json:"winbox"`
		}
		if err := json.Unmarshal([]byte(trimmedBody), &payload); err != nil {
			writeResponse(w, r, http.StatusBadRequest, "ERROR format json tidak valid", JSONResponse{
				Status:    "error",
				Message:   "format json tidak valid",
				RequestID: reqID,
			})
			return netip.Addr{}, "", false, err
		}
		rawIP = payload.IP
		rawHostname = payload.Hostname
		if rawHostname == "" {
			rawHostname = payload.Host
		}
		winbox = parseJSONBool(payload.Winbox)
	} else {
		values, err := url.ParseQuery(trimmedBody)
		if err != nil {
			writeResponse(w, r, http.StatusBadRequest, "ERROR format form tidak valid", JSONResponse{
				Status:    "error",
				Message:   "format form tidak valid",
				RequestID: reqID,
			})
			return netip.Addr{}, "", false, err
		}

		rawValues, exists := values["ip"]
		if exists && len(rawValues) > 0 {
			rawIP = rawValues[0]
		}
		rawHostname = values.Get("hostname")
		if rawHostname == "" {
			rawHostname = values.Get("host")
		}
		winbox = parseBoolParam(values, "winbox")
	}

	// Verify "ip" parameter presence
	if strings.TrimSpace(rawIP) == "" {
		writeResponse(w, r, http.StatusBadRequest, "ERROR ip wajib diisi", JSONResponse{
			Status:    "error",
			Message:   "ip wajib diisi",
			RequestID: reqID,
		})
		return netip.Addr{}, "", false, ipcheck.ErrIPRequired
	}

	SetTargetIP(r.Context(), strings.TrimSpace(rawIP))

	addr, err := h.validator.Validate(rawIP)
	if err != nil {
		switch {
		case errors.Is(err, ipcheck.ErrIPRequired):
			writeResponse(w, r, http.StatusBadRequest, "ERROR ip wajib diisi", JSONResponse{
				Status:    "error",
				Message:   "ip wajib diisi",
				RequestID: reqID,
			})
		case errors.Is(err, ipcheck.ErrIPInvalid):
			writeResponse(w, r, http.StatusBadRequest, "ERROR ip tidak valid", JSONResponse{
				Status:    "error",
				Message:   "ip tidak valid",
				RequestID: reqID,
			})
		case errors.Is(err, ipcheck.ErrIPForbidden):
			writeResponse(w, r, http.StatusBadRequest, "ERROR ip tidak diizinkan", JSONResponse{
				Status:    "error",
				Message:   "ip tidak diizinkan",
				RequestID: reqID,
			})
		default:
			writeResponse(w, r, http.StatusBadRequest, "ERROR ip tidak valid", JSONResponse{
				Status:    "error",
				Message:   "ip tidak valid",
				RequestID: reqID,
			})
		}
		return netip.Addr{}, "", false, err
	}

	SetTargetIP(r.Context(), addr.String())

	// Extract or resolve target hostname
	hostname := mikrotik.SanitizeHostname(rawHostname)
	if hostname == "" {
		hostname = mikrotik.ResolveHostname(r.Context(), addr.String())
	}

	return addr, hostname, winbox, nil
}

// HandleWhitelist handles POST (whitelist add / extend) and DELETE (whitelist remove).
func (h *Handler) HandleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handlePostWhitelist(w, r)
	case http.MethodDelete:
		h.handleDeleteWhitelist(w, r)
	default:
		SetAction(r.Context(), "rejected")
		http.NotFound(w, r)
	}
}

// handlePostWhitelist handles POST /v1/whitelist.
func (h *Handler) handlePostWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := GetRequestID(ctx)

	addr, hostname, winbox, err := h.parseIPForm(w, r)
	if err != nil {
		SetAction(ctx, "rejected")
		return
	}

	res, err := h.mkClient.Whitelist(ctx, addr.String(), hostname)
	if err != nil {
		SetAction(ctx, "rejected")
		h.logger.Error("mikrotik whitelist operation failed", "request_id", reqID, "ip", addr.String(), "error", err)
		writeResponse(w, r, http.StatusBadGateway, fmt.Sprintf("ERROR internal (req=%s)", reqID), JSONResponse{
			Status:    "error",
			Message:   "internal error",
			RequestID: reqID,
		})
		return
	}

	var winboxAllowed bool
	if winbox {
		if err := h.mkClient.AllowWinbox(ctx, addr.String()); err != nil {
			SetAction(ctx, "rejected")
			h.logger.Error("mikrotik allow winbox failed", "request_id", reqID, "ip", addr.String(), "error", err)
			writeResponse(w, r, http.StatusBadGateway, fmt.Sprintf("ERROR internal (req=%s)", reqID), JSONResponse{
				Status:    "error",
				Message:   "internal error (winbox)",
				RequestID: reqID,
			})
			return
		}
		winboxAllowed = true
		h.logger.Info("allowed winbox access for ip", "request_id", reqID, "ip", addr.String())
	}

	actionStr := string(res.Action)
	SetAction(ctx, actionStr)

	if res.RemovedFromAbuse {
		h.logger.Info("ip was removed from port-forward-abuse list before whitelisting",
			"request_id", reqID,
			"ip", res.IP,
			"hostname", res.Hostname,
			"action", res.Action,
		)
	}

	expiresStr := res.ExpiresAt.Format(time.RFC3339)
	textResp := fmt.Sprintf("OK ip=%s expires=%s", res.IP, expiresStr)
	if winboxAllowed {
		textResp += " winbox=allowed"
	}

	jsonAction := "added"
	if res.Action == mikrotik.ActionExtended {
		jsonAction = "extended"
	}

	writeResponse(w, r, http.StatusOK, textResp, JSONResponse{
		Status:           "ok",
		IP:               res.IP,
		Hostname:         res.Hostname,
		Expires:          expiresStr,
		Action:           jsonAction,
		RequestID:        reqID,
		RemovedFromAbuse: res.RemovedFromAbuse,
		WinboxAllowed:    winboxAllowed,
	})
}

// handleDeleteWhitelist handles DELETE /v1/whitelist.
func (h *Handler) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := GetRequestID(ctx)

	addr, _, winbox, err := h.parseIPForm(w, r)
	if err != nil {
		SetAction(ctx, "rejected")
		return
	}

	err = h.mkClient.Remove(ctx, addr.String())
	if err != nil {
		SetAction(ctx, "rejected")
		switch {
		case errors.Is(err, mikrotik.ErrNotFound):
			writeResponse(w, r, http.StatusNotFound, "ERROR ip tidak ditemukan", JSONResponse{
				Status:    "error",
				Message:   "ip tidak ditemukan",
				RequestID: reqID,
			})
		case errors.Is(err, mikrotik.ErrNotManaged):
			writeResponse(w, r, http.StatusForbidden, "ERROR ip tidak diizinkan untuk dihapus", JSONResponse{
				Status:    "error",
				Message:   "ip tidak diizinkan untuk dihapus",
				RequestID: reqID,
			})
		default:
			h.logger.Error("mikrotik remove operation failed", "request_id", reqID, "ip", addr.String(), "error", err)
			writeResponse(w, r, http.StatusBadGateway, fmt.Sprintf("ERROR internal (req=%s)", reqID), JSONResponse{
				Status:    "error",
				Message:   "internal error",
				RequestID: reqID,
			})
		}
		return
	}

	var winboxRemoved bool
	if winbox {
		if err := h.mkClient.RemoveWinbox(ctx, addr.String()); err != nil {
			h.logger.Error("mikrotik remove winbox failed", "request_id", reqID, "ip", addr.String(), "error", err)
		} else {
			winboxRemoved = true
			h.logger.Info("removed winbox access for ip", "request_id", reqID, "ip", addr.String())
		}
	}

	SetAction(ctx, string(mikrotik.ActionRemoved))

	textResp := fmt.Sprintf("OK ip=%s action=removed", addr.String())
	if winboxRemoved {
		textResp += " winbox=removed"
	}

	writeResponse(w, r, http.StatusOK, textResp, JSONResponse{
		Status:        "ok",
		IP:            addr.String(),
		Action:        "removed",
		RequestID:     reqID,
		WinboxRemoved: winboxRemoved,
	})
}

// HandleHealthz handles GET /healthz.
func (h *Handler) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := GetRequestID(ctx)

	if r.Method != http.MethodGet {
		SetAction(ctx, "rejected")
		http.NotFound(w, r)
		return
	}

	if err := h.mkClient.Ping(ctx); err != nil {
		SetAction(ctx, "health_check_failed")
		h.logger.Error("health check ping to mikrotik failed", "request_id", reqID, "error", err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintln(w, "ERROR service unavailable")
		return
	}

	SetAction(ctx, "health_check_ok")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "ok")
}

// SetupRouter initializes the HTTP multiplexer with all configured routes and middleware.
// If authBearerToken is non-empty, /v1/whitelist routes are protected with BearerAuthMiddleware.
// /healthz remains unauthenticated for health check probes.
func SetupRouter(h *Handler, authBearerToken string, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	whitelistHandler := BearerAuthMiddleware(authBearerToken, logger)(http.HandlerFunc(h.HandleWhitelist))
	mux.Handle("/v1/whitelist", whitelistHandler)
	mux.HandleFunc("/healthz", h.HandleHealthz)

	// Wrap with LoggingMiddleware
	return LoggingMiddleware(logger)(mux)
}
