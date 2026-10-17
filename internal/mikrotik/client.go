package mikrotik

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-routeros/routeros/v3"
	"whitelist-mikrotik/internal/config"
)

var (
	// ErrNotFound is returned when the requested IP is not in the whitelist address list.
	ErrNotFound = errors.New("address-list entry not found")

	// ErrNotManaged is returned when the address-list entry does not have a "wl|" comment prefix (e.g., admin manual entry).
	ErrNotManaged = errors.New("address-list entry is not managed by whitelist service")
)

// Action represents the outcome of a whitelist operation.
type Action string

const (
	ActionAdded    Action = "whitelist_add"
	ActionExtended Action = "whitelist_extend"
	ActionRemoved  Action = "whitelist_remove"
)

// WhitelistResult holds the details of a successful whitelist addition or extension.
type WhitelistResult struct {
	Action           Action
	IP               string
	ExpiresAt        time.Time
	RemovedFromAbuse bool
}

// Client defines the interface for interacting with MikroTik RouterOS firewall address lists.
type Client interface {
	Whitelist(ctx context.Context, ip string) (*WhitelistResult, error)
	Remove(ctx context.Context, ip string) error
	Ping(ctx context.Context) error
	Close() error
}

// DialFunc defines the function signature for dialing a RouterOS instance.
type DialFunc func(addr, user, pass string, timeout time.Duration) (*routeros.Client, error)

// RouterOSClient implements Client using the official RouterOS API.
type RouterOSClient struct {
	mu       sync.Mutex
	cfg      *config.Config
	conn     *routeros.Client
	logger   *slog.Logger
	dialFunc DialFunc
}

// NewClient creates a new RouterOSClient.
func NewClient(cfg *config.Config, logger *slog.Logger) *RouterOSClient {
	return &RouterOSClient{
		cfg:      cfg,
		logger:   logger,
		dialFunc: routeros.DialTimeout,
	}
}

// SetDialFunc overrides the dialer function, primarily used for unit testing.
func (c *RouterOSClient) SetDialFunc(fn DialFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialFunc = fn
}

// connectLocked establishes the RouterOS connection if not already connected.
// Caller must hold c.mu.
func (c *RouterOSClient) connectLocked() error {
	if c.conn != nil {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", c.cfg.MikrotikHost, c.cfg.MikrotikPort)
	dialTimeout := 5 * time.Second

	c.logger.Debug("connecting to mikrotik", "addr", addr, "user", c.cfg.MikrotikUser)
	conn, err := c.dialFunc(addr, c.cfg.MikrotikUser, c.cfg.MikrotikPassword, dialTimeout)
	if err != nil {
		return fmt.Errorf("routeros dial failed: %w", err)
	}

	c.conn = conn
	return nil
}

// closeLocked closes the active connection.
// Caller must hold c.mu.
func (c *RouterOSClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Close closes the underlying RouterOS client connection.
func (c *RouterOSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	return nil
}

// runCommand executes sentences on RouterOS with a 5-second per-command timeout,
// reusing the connection and retrying once upon connection failure.
func (c *RouterOSClient) runCommand(ctx context.Context, sentences ...string) (*routeros.Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure connection is established
	if c.conn == nil {
		if err := c.connectLocked(); err != nil {
			return nil, err
		}
	}

	// 5-second command timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reply, err := c.conn.RunContext(cmdCtx, sentences...)
	if err == nil {
		return reply, nil
	}

	// If failed and caller's context is still active, retry once with reconnect
	if ctx.Err() == nil {
		c.logger.Warn("mikrotik command failed, retrying once after reconnect", "error", err)
		c.closeLocked()

		if connErr := c.connectLocked(); connErr == nil {
			retryCtx, retryCancel := context.WithTimeout(ctx, 5*time.Second)
			defer retryCancel()

			reply, retryErr := c.conn.RunContext(retryCtx, sentences...)
			if retryErr == nil {
				return reply, nil
			}
			err = retryErr
		}
	}

	return nil, err
}

type addressListEntry struct {
	id      string
	list    string
	address string
	comment string
}

// findEntries queries /ip/firewall/address-list for entries matching the given list and IP.
func (c *RouterOSClient) findEntries(ctx context.Context, listName, ip string) ([]addressListEntry, error) {
	reply, err := c.runCommand(ctx, "/ip/firewall/address-list/print", "?list="+listName, "?address="+ip, "?#&")
	if err != nil {
		return nil, fmt.Errorf("mikrotik query address-list error: %w", err)
	}

	var entries []addressListEntry
	for _, sen := range reply.Re {
		if sen.Map["list"] == listName && sen.Map["address"] == ip {
			entries = append(entries, addressListEntry{
				id:      sen.Map[".id"],
				list:    sen.Map["list"],
				address: sen.Map["address"],
				comment: sen.Map["comment"],
			})
		}
	}

	return entries, nil
}

// Whitelist checks if the IP is present in the abuse list (e.g. "port-forward-abuse").
// If found, it removes the entry from the abuse list first.
// Then it checks if the IP is already in the whitelist address list.
// If found, it extends the timeout with "set". If not found, it adds the IP with "add"
// and a "wl|<RFC3339>" comment.
func (c *RouterOSClient) Whitelist(ctx context.Context, ip string) (*WhitelistResult, error) {
	abuseListName := c.cfg.PortForwardAbuseListName
	listName := c.cfg.WhitelistListName
	now := time.Now().In(c.cfg.Location)
	rfc3339Now := now.Format(time.RFC3339)
	comment := fmt.Sprintf("wl|%s", rfc3339Now)
	expiresAt := now.Add(c.cfg.WhitelistDuration)

	// 1. Check if the target IP exists in "port-forward-abuse" address list. If so, remove it.
	removedFromAbuse := false
	if strings.TrimSpace(abuseListName) != "" {
		abuseEntries, err := c.findEntries(ctx, abuseListName, ip)
		if err != nil {
			return nil, fmt.Errorf("mikrotik query abuse address-list error: %w", err)
		}

		if len(abuseEntries) > 0 {
			removedFromAbuse = true
			for _, entry := range abuseEntries {
				if _, err := c.runCommand(ctx, "/ip/firewall/address-list/remove", "=.id="+entry.id); err != nil {
					// Ignore "no such item" if already deleted concurrently or expired
					if !strings.Contains(strings.ToLower(err.Error()), "no such item") {
						return nil, fmt.Errorf("mikrotik remove abuse address-list error: %w", err)
					}
				}
			}
			c.logger.Info("removed target IP from abuse address list",
				"ip", ip,
				"list", abuseListName,
				"count", len(abuseEntries),
			)
		}
	}

	// 2. Search for existing entry in the whitelist address list
	whitelistEntries, err := c.findEntries(ctx, listName, ip)
	if err != nil {
		return nil, fmt.Errorf("mikrotik query address-list error: %w", err)
	}

	if len(whitelistEntries) > 0 {
		existing := whitelistEntries[0]
		// Update existing entry. Only update comment if managed by wl (starts with "wl|")
		var setArgs []string
		if strings.HasPrefix(existing.comment, "wl|") {
			setArgs = []string{"/ip/firewall/address-list/set", "=.id=" + existing.id, "=timeout=" + c.cfg.WhitelistTTL, "=comment=" + comment}
		} else {
			setArgs = []string{"/ip/firewall/address-list/set", "=.id=" + existing.id, "=timeout=" + c.cfg.WhitelistTTL}
		}

		if _, err := c.runCommand(ctx, setArgs...); err != nil {
			return nil, fmt.Errorf("mikrotik set address-list error: %w", err)
		}

		return &WhitelistResult{
			Action:           ActionExtended,
			IP:               ip,
			ExpiresAt:        expiresAt,
			RemovedFromAbuse: removedFromAbuse,
		}, nil
	}

	// Add new entry
	addArgs := []string{
		"/ip/firewall/address-list/add",
		"=list=" + listName,
		"=address=" + ip,
		"=timeout=" + c.cfg.WhitelistTTL,
		"=comment=" + comment,
	}

	if _, err := c.runCommand(ctx, addArgs...); err != nil {
		return nil, fmt.Errorf("mikrotik add address-list error: %w", err)
	}

	return &WhitelistResult{
		Action:           ActionAdded,
		IP:               ip,
		ExpiresAt:        expiresAt,
		RemovedFromAbuse: removedFromAbuse,
	}, nil
}

// Remove removes the IP from the whitelist address list only if its comment starts with "wl|".
func (c *RouterOSClient) Remove(ctx context.Context, ip string) error {
	listName := c.cfg.WhitelistListName

	entries, err := c.findEntries(ctx, listName, ip)
	if err != nil {
		return fmt.Errorf("mikrotik query address-list error: %w", err)
	}

	if len(entries) == 0 {
		return ErrNotFound
	}

	target := entries[0]

	// Protect entries created manually by administrators
	if !strings.HasPrefix(target.comment, "wl|") {
		return ErrNotManaged
	}

	if _, err := c.runCommand(ctx, "/ip/firewall/address-list/remove", "=.id="+target.id); err != nil {
		return fmt.Errorf("mikrotik remove address-list error: %w", err)
	}

	return nil
}

// Ping checks whether RouterOS is responsive.
func (c *RouterOSClient) Ping(ctx context.Context) error {
	_, err := c.runCommand(ctx, "/system/resource/print")
	if err != nil {
		return fmt.Errorf("mikrotik health ping failed: %w", err)
	}
	return nil
}
