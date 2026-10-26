// Package oidc implements a minimal OpenID Connect relying party (Authorization
// Code flow + PKCE) using only the Go standard library. It is designed for
// Authentik but works with any spec-compliant OIDC provider.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid id_token")
	ErrNotAllowed   = errors.New("user is not a member of any allowed group")
)

// clockSkew tolerates small clock differences between this host and the IdP.
const clockSkew = 2 * time.Minute

// Config holds the relying party settings.
type Config struct {
	IssuerURL     string // e.g. https://auth.example.com/application/o/wlservice/
	ClientID      string
	ClientSecret  string
	RedirectURL   string   // e.g. https://wl.example.com/auth/callback
	Scopes        []string // defaults to openid profile email
	AllowedGroups []string // empty = any authenticated user
	PostLogoutURL string   // optional redirect after IdP logout
}

// Claims are the identity claims extracted from a verified id_token.
type Claims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// DisplayName returns the best human-readable identifier for the user.
func (c *Claims) DisplayName() string {
	for _, v := range []string{c.PreferredUsername, c.Email, c.Name, c.Subject} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "oidc-user"
}

type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Provider is a lazily discovered OIDC provider. Discovery happens on first
// use so the service can start even while the IdP is temporarily unreachable.
type Provider struct {
	cfg    Config
	client *http.Client

	mu        sync.Mutex
	doc       *discoveryDoc
	keys      map[string]crypto.PublicKey
	keysFetch time.Time
}

// NewProvider creates a provider. No network calls are made here.
func NewProvider(cfg Config) *Provider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	hasOpenID := false
	for _, s := range cfg.Scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}
	return &Provider{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *Provider) discover(ctx context.Context) (*discoveryDoc, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.doc != nil {
		return p.doc, nil
	}

	wellKnown := strings.TrimSuffix(p.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	var doc discoveryDoc
	if err := p.getJSON(ctx, wellKnown, &doc); err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.Issuer == "" {
		return nil, errors.New("oidc discovery document is incomplete")
	}
	if strings.TrimSuffix(doc.Issuer, "/") != strings.TrimSuffix(p.cfg.IssuerURL, "/") {
		return nil, fmt.Errorf("oidc issuer mismatch: configured %q, provider reports %q", p.cfg.IssuerURL, doc.Issuer)
	}
	p.doc = &doc
	return p.doc, nil
}

func (p *Provider) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: unexpected status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// AuthCodeURL builds the authorization redirect URL with PKCE (S256).
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, codeVerifier string) (string, error) {
	doc, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	challenge := sha256.Sum256([]byte(codeVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(doc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return doc.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange trades the authorization code for tokens, verifies the id_token,
// enforces the group allow-list and returns the identity claims along with the
// raw id_token (needed as id_token_hint on logout).
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*Claims, string, error) {
	doc, err := p.discover(ctx)
	if err != nil {
		return nil, "", err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"client_id":     {p.cfg.ClientID},
		"code_verifier": {codeVerifier},
	}
	// client_secret_post: avoids Basic-auth encoding ambiguities across IdPs.
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	var tok struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return nil, "", fmt.Errorf("token response decode failed (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tok.Error != "" {
		return nil, "", fmt.Errorf("token endpoint error (status %d): %s %s", resp.StatusCode, tok.Error, tok.ErrorDescription)
	}
	if tok.IDToken == "" {
		return nil, "", errors.New("token response has no id_token (is the 'openid' scope granted?)")
	}

	claims, err := p.VerifyIDToken(ctx, tok.IDToken, nonce)
	if err != nil {
		return nil, "", err
	}
	if !p.groupAllowed(claims.Groups) {
		return claims, "", ErrNotAllowed
	}
	return claims, tok.IDToken, nil
}

func (p *Provider) groupAllowed(groups []string) bool {
	if len(p.cfg.AllowedGroups) == 0 {
		return true
	}
	for _, want := range p.cfg.AllowedGroups {
		for _, have := range groups {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

// VerifyIDToken validates signature, issuer, audience, expiry and nonce.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, nonce string) (*Claims, error) {
	doc, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed JWT", ErrInvalidToken)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("%w: bad header: %v", ErrInvalidToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrInvalidToken)
	}
	signed := []byte(parts[0] + "." + parts[1])

	if err := p.verifySignature(ctx, doc, header.Alg, header.Kid, signed, sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var payload struct {
		Claims
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		Azp      string          `json:"azp"`
		Exp      json.Number     `json:"exp"`
		Iat      json.Number     `json:"iat"`
		Nonce    string          `json:"nonce"`
	}
	if err := decodeSegment(parts[1], &payload); err != nil {
		return nil, fmt.Errorf("%w: bad payload: %v", ErrInvalidToken, err)
	}

	if payload.Issuer != doc.Issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
	}

	var auds []string
	var single string
	if err := json.Unmarshal(payload.Audience, &single); err == nil {
		auds = []string{single}
	} else if err := json.Unmarshal(payload.Audience, &auds); err != nil {
		return nil, fmt.Errorf("%w: bad aud claim", ErrInvalidToken)
	}
	audOK := false
	for _, a := range auds {
		if a == p.cfg.ClientID {
			audOK = true
		}
	}
	if !audOK {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}
	if len(auds) > 1 && payload.Azp != "" && payload.Azp != p.cfg.ClientID {
		return nil, fmt.Errorf("%w: azp mismatch", ErrInvalidToken)
	}

	exp, err := payload.Exp.Int64()
	if err != nil {
		return nil, fmt.Errorf("%w: missing exp", ErrInvalidToken)
	}
	if time.Now().After(time.Unix(exp, 0).Add(clockSkew)) {
		return nil, fmt.Errorf("%w: token expired", ErrInvalidToken)
	}

	if subtle.ConstantTimeCompare([]byte(payload.Nonce), []byte(nonce)) != 1 || nonce == "" {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
	}
	if payload.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}

	claims := payload.Claims
	return &claims, nil
}

func (p *Provider) verifySignature(ctx context.Context, doc *discoveryDoc, alg, kid string, signed, sig []byte) error {
	switch alg {
	case "HS256", "HS384", "HS512":
		// Authentik uses HMAC with the client secret when no signing key is set.
		if p.cfg.ClientSecret == "" {
			return errors.New("HMAC-signed token but no client secret configured")
		}
		var h func() hash.Hash
		switch alg {
		case "HS256":
			h = sha256.New
		case "HS384":
			h = sha512.New384
		default:
			h = sha512.New
		}
		mac := hmac.New(h, []byte(p.cfg.ClientSecret))
		mac.Write(signed)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("HMAC signature mismatch")
		}
		return nil
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}

	key, err := p.publicKey(ctx, doc, kid)
	if err != nil {
		return err
	}

	var hashFn crypto.Hash
	switch alg[2:] {
	case "256":
		hashFn = crypto.SHA256
	case "384":
		hashFn = crypto.SHA384
	default:
		hashFn = crypto.SHA512
	}
	hasher := hashFn.New()
	hasher.Write(signed)
	digest := hasher.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") {
			return errors.New("key type does not match alg")
		}
		return rsa.VerifyPKCS1v15(k, hashFn, digest, sig)
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return errors.New("key type does not match alg")
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("bad ECDSA signature length")
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			return errors.New("ECDSA signature mismatch")
		}
		return nil
	default:
		return errors.New("unsupported key type")
	}
}

// publicKey returns the JWKS key for kid, refetching the key set (at most once
// per minute) when the kid is unknown to handle IdP key rotation.
func (p *Provider) publicKey(ctx context.Context, doc *discoveryDoc, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if k := p.lookupKey(kid); k != nil {
		return k, nil
	}
	if time.Since(p.keysFetch) < time.Minute && p.keys != nil {
		return nil, fmt.Errorf("no JWKS key for kid %q", kid)
	}
	if doc.JWKSURI == "" {
		return nil, errors.New("provider has no jwks_uri")
	}

	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, doc.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	p.keys = keys
	p.keysFetch = time.Now()

	if k := p.lookupKey(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

func (p *Provider) lookupKey(kid string) crypto.PublicKey {
	if p.keys == nil {
		return nil
	}
	if k, ok := p.keys[kid]; ok {
		return k
	}
	// Tokens without kid are acceptable only when the set has a single key.
	if kid == "" && len(p.keys) == 1 {
		for _, k := range p.keys {
			return k
		}
	}
	return nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

// EndSessionURL builds the RP-initiated logout URL. Returns "" if the provider
// does not advertise an end_session_endpoint or discovery fails.
func (p *Provider) EndSessionURL(ctx context.Context, idTokenHint string) string {
	doc, err := p.discover(ctx)
	if err != nil || doc.EndSessionEndpoint == "" {
		return ""
	}
	q := url.Values{}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if p.cfg.PostLogoutURL != "" {
		q.Set("post_logout_redirect_uri", p.cfg.PostLogoutURL)
		q.Set("client_id", p.cfg.ClientID)
	}
	if len(q) == 0 {
		return doc.EndSessionEndpoint
	}
	sep := "?"
	if strings.Contains(doc.EndSessionEndpoint, "?") {
		sep = "&"
	}
	return doc.EndSessionEndpoint + sep + q.Encode()
}

// RandomString returns a URL-safe random string with n bytes of entropy.
func RandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeSegment(seg string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	return dec.Decode(out)
}
