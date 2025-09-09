package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type ServerInfo struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	Port           int       `json:"port"`
	CurrentPlayers int       `json:"currentPlayers,omitempty"`
	MaxPlayers     int       `json:"maxPlayers,omitempty"`
	LastSeen       time.Time `json:"lastSeen"`
}

type HeartbeatClaims struct {
	jwt.RegisteredClaims
}

type HeartbeatBody struct {
	Name           string `json:"name,omitempty"`
	Address        string `json:"address,omitempty"`
	Port           int    `json:"port"`
	APIPort        int    `json:"apiPort,omitempty"`
	CurrentPlayers int    `json:"currentPlayers,omitempty"`
	MaxPlayers     int    `json:"maxPlayers,omitempty"`
}

type Registry struct {
	mu     sync.RWMutex
	stores map[string]*ServerInfo
	ttl    time.Duration
}

func NewRegistry(ttl time.Duration) *Registry {
	return &Registry{
		stores: make(map[string]*ServerInfo),
		ttl:    ttl,
	}
}

func (r *Registry) Get(id string) *ServerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.stores[id]; ok {
		c := *s
		return &c
	}
	return nil
}

func (r *Registry) Upsert(s ServerInfo) {
	if s.ID == "" {
		s.ID = s.Address + ":" + strconv.Itoa(s.Port)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s.LastSeen = time.Now().UTC()
	r.stores[s.ID] = &s
}

func (r *Registry) Touch(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.stores[id]; ok {
		s.LastSeen = time.Now().UTC()
		return true
	}
	return false
}

func (r *Registry) ListAlive(filter func(*ServerInfo) bool) []*ServerInfo {
	deadline := time.Now().UTC().Add(-r.ttl)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ServerInfo, 0, len(r.stores))
	for _, s := range r.stores {
		if s.LastSeen.Before(deadline) {
			continue
		}
		if filter != nil && !filter(s) {
			continue
		}
		cpy := *s
		out = append(out, &cpy)
	}
	return out
}

func (r *Registry) PruneExpired() int {
	deadline := time.Now().UTC().Add(-r.ttl)
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for id, s := range r.stores {
		if s.LastSeen.Before(deadline) {
			delete(r.stores, id)
			removed++
		}
	}
	return removed
}

func heartbeatHandler(reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var body HeartbeatBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		senderIP := clientIP(r)
		if senderIP == nil {
			http.Error(w, "could not determine sender IP", http.StatusBadRequest)
			return
		}

		tokenString := ""
		if ah := r.Header.Get("Authorization"); ah != "" {
			parts := strings.SplitN(ah, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				tokenString = strings.TrimSpace(parts[1])
			}
		}
		if tokenString == "" {
			http.Error(w, "missing JWT bearer token", http.StatusBadRequest)
			return
		}

		announcedIP := strings.TrimSpace(body.Address)
		if announcedIP == "" {
			announcedIP = senderIP.String()
		}
		body.Address = announcedIP
		keyFunc := func(t *jwt.Token) (any, error) {
			// Restrict algorithms to RSA variants
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
			}
			// Extract claims (unverified at this stage)
			if c, ok := t.Claims.(*HeartbeatClaims); ok {
				issuer := c.RegisteredClaims.Issuer
				if issuer == "" {
					issuer = "http://" + announcedIP + ":" + strconv.Itoa(body.APIPort)
				}
				// Resolve public key using issuer and the kid from the JWT
				var kid string
				if hv, ok := t.Header["kid"]; ok {
					if s, ok := hv.(string); ok {
						kid = s
					}
				}
				pk, err := resolvePublicKey(issuer, kid)
				if err != nil {
					return nil, err
				}
				return pk, nil
			}
			return nil, errors.New("invalid claims type")
		}

		token, err := jwt.ParseWithClaims(tokenString, &HeartbeatClaims{}, keyFunc, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))
		if err != nil || !token.Valid {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(*HeartbeatClaims)
		if !ok {
			http.Error(w, "invalid claims", http.StatusUnauthorized)
			return
		}

		if body.Port == 0 {
			http.Error(w, "port is required", http.StatusBadRequest)
			return
		}
		serverId := claims.RegisteredClaims.Subject
		if serverId == "" {
			http.Error(w, "subject is required", http.StatusBadRequest)
			return
		}

		if existing := reg.Get(serverId); existing != nil {
			if existing.Address != body.Address || existing.Port != body.Port {
				// TODO for verified servers, this will be allowed
				http.Error(w, "address or port changed for existing ID", http.StatusBadRequest)
				return
			}
			reg.Touch(serverId)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		if body.CurrentPlayers < 0 || body.MaxPlayers < 0 {
			http.Error(w, "invalid players data", http.StatusBadRequest)
			return
		}
		if len(body.Name) > 200 {
			http.Error(w, "name too long", http.StatusBadRequest)
			return
		}

		s := ServerInfo{
			ID:             serverId,
			Name:           body.Name,
			Address:        body.Address,
			Port:           body.Port,
			CurrentPlayers: body.CurrentPlayers,
			MaxPlayers:     body.MaxPlayers,
		}
		reg.Upsert(s)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func listServersHandler(reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		servers := reg.ListAlive(nil)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":   len(servers),
			"servers": servers,
		})
	}
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if i, err := strconv.Atoi(v); err == nil {
			return time.Duration(i) * time.Second
		}
	}
	return def
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := getenv("PORT", "8080")
	ttl := getenvDuration("HEARTBEAT_TTL", 60*time.Second)
	pruneEvery := getenvDuration("PRUNE_INTERVAL", 30*time.Second)

	reg := NewRegistry(ttl)

	mux := http.NewServeMux()
	mux.HandleFunc("/heartbeat", heartbeatHandler(reg))
	mux.HandleFunc("/servers", listServersHandler(reg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(pruneEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				removed := reg.PruneExpired()
				if removed > 0 {
					log.Printf("pruned %d expired servers", removed)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		log.Printf("telescope listening on :%s (ttl=%s prune=%s)", port, ttl, pruneEvery)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Printf("server stopped")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		cip := clientIP(r)
		ripHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		if cip != nil {
			log.Printf("%s %s from=%s (remote=%s) %s", r.Method, r.URL.Path, cip.String(), ripHost, time.Since(start))
		} else {
			log.Printf("%s %s remote=%s %s", r.Method, r.URL.Path, ripHost, time.Since(start))
		}
	})
}

var trustedProxyNets []net.IPNet
var trustedOnce sync.Once

func loadTrustedProxies() {
	trustedOnce.Do(func() {
		list := os.Getenv("PROXY_TRUSTED_ADDRESSES")
		if list == "" {
			trustedProxyNets = nil
			return
		}
		var nets []net.IPNet
		for _, part := range splitAndTrim(list, ',') {
			if part == "" {
				continue
			}
			if ip := net.ParseIP(part); ip != nil {
				// Convert single IP to /32 or /128 net
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				mask := net.CIDRMask(bits, bits)
				nets = append(nets, net.IPNet{IP: ip.Mask(mask), Mask: mask})
				continue
			}
			if _, n, err := net.ParseCIDR(part); err == nil {
				nets = append(nets, *n)
				continue
			}
			log.Printf("ignoring invalid PROXY_TRUSTED_ADDRESSES entry: %q", part)
		}
		trustedProxyNets = nets
	})
}

func splitAndTrim(s string, sep rune) []string {
	parts := strings.Split(s, string(sep))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if tp := strings.TrimSpace(p); tp != "" {
			out = append(out, tp)
		}
	}
	return out
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func isTrustedProxy(ip net.IP) bool {
	loadTrustedProxies()
	if len(trustedProxyNets) == 0 {
		return true
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseFirstIP(list string) net.IP {
	// X-Forwarded-For: client, proxy1, proxy2 ... (left-most is original client)
	for _, p := range splitAndTrim(list, ',') {
		if p == "" {
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			return ip
		}
	}
	return nil
}

var proxyHeader string
var proxyHeaderOnce sync.Once

func getProxyHeader() string {
	proxyHeaderOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv("PROXY_HEADERS"))
		switch strings.ToLower(v) {
		case "", "cloudflare", "xforwarded":
			proxyHeader = strings.ToLower(v)
		default:
			log.Printf("invalid PROXY_HEADERS=%q; allowed: cloudflare, xforwarded. Ignoring.", v)
			proxyHeader = ""
		}
	})
	return proxyHeader
}

func clientIP(r *http.Request) net.IP {
	rip := remoteIP(r)
	if rip == nil {
		return nil
	}
	if isTrustedProxy(rip) {
		switch getProxyHeader() {
		case "cloudflare":
			if v := r.Header.Get("CF-Connecting-IP"); v != "" {
				if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
					return ip
				}
			}
		case "xforwarded":
			if v := r.Header.Get("X-Forwarded-For"); v != "" {
				if ip := parseFirstIP(v); ip != nil {
					return ip
				}
			}
		}
	}
	return rip
}

func resolvePublicKey(issuer, kid string) (*rsa.PublicKey, error) {
	// TODO in the future, verified servers will provide a known registered issuer id under which we can lookup the stored public key instead of just trusting the announced ip
	pk, err := fetchPublicKeyHTTP(issuer, kid)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func fetchPublicKeyHTTP(issuer string, kid string) (*rsa.PublicKey, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	jwksURL := fmt.Sprintf("%s/heartbeat/jwks", issuer)
	if pk, err := fetchJWKS(client, jwksURL, kid); err == nil && pk != nil {
		return pk, nil
	}
	return nil, errors.New("failed to fetch public key")
}

type jwkKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

func fetchJWKS(client *http.Client, url string, kid string) (*rsa.PublicKey, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("jwks contains no keys")
	}
	// Prefer matching kid when provided
	if kid != "" {
		for _, k := range doc.Keys {
			if strings.EqualFold(k.Kty, "RSA") && k.Kid == kid {
				return jwkToRSAPublicKey(k)
			}
		}
	}
	// Otherwise, pick the first RSA key
	for _, k := range doc.Keys {
		if strings.EqualFold(k.Kty, "RSA") {
			return jwkToRSAPublicKey(k)
		}
	}
	return nil, errors.New("no RSA key in jwks")
}

func jwkToRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	if !strings.EqualFold(k.Kty, "RSA") {
		return nil, fmt.Errorf("unsupported kty: %s", k.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("invalid n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("invalid e: %w", err)
	}
	// Convert eBytes (big-endian) to int
	e := 0
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	if e <= 0 {
		return nil, errors.New("invalid exponent")
	}
	n := new(big.Int).SetBytes(nBytes)
	return &rsa.PublicKey{N: n, E: e}, nil
}
