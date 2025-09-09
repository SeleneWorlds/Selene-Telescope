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

func writeAPIError(w http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		log.Printf("API error: %s: %v", msg, err)
	} else {
		log.Printf("API error: %s", msg)
	}
	http.Error(w, msg, code)
}

type tokenBucket struct {
	capacity   float64
	tokens     float64
	refillRate float64
	last       time.Time
}

func (b *tokenBucket) allow(now time.Time, cost float64) bool {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = minFloat(b.capacity, b.tokens+elapsed*b.refillRate)
		b.last = now
	}
	if b.tokens >= cost {
		b.tokens -= cost
		return true
	}
	return false
}

type IPRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64
	burst   float64
}

func NewIPRateLimiter(rate float64, burst int) *IPRateLimiter {
	if rate <= 0 {
		rate = 5
	}
	if burst <= 0 {
		burst = 10
	}
	return &IPRateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   float64(burst),
	}
}

func (l *IPRateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{capacity: l.burst, tokens: l.burst, refillRate: l.rate, last: now}
		l.buckets[key] = b
	}
	allowed := b.allow(now, 1)
	l.mu.Unlock()
	return allowed
}

var limiterOnce sync.Once
var hbLimiter *IPRateLimiter

func getHeartbeatLimiter() *IPRateLimiter {
	limiterOnce.Do(func() {
		// Configure via env: HEARTBEAT_RPS (float), HEARTBEAT_BURST (int)
		// Defaults target ~1 heartbeat every 30s with small burst.
		rate := 1.0 / 30.0
		if v := os.Getenv("HEARTBEAT_RPS"); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
				rate = f
			}
		}
		burst := 2
		if v := os.Getenv("HEARTBEAT_BURST"); v != "" {
			if i, err := strconv.Atoi(v); err == nil && i > 0 {
				burst = i
			}
		}
		hbLimiter = NewIPRateLimiter(rate, burst)
		log.Printf("heartbeat rate limiter: rate=%.2f rps burst=%d", rate, burst)
	})
	return hbLimiter
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

type cachedKey struct {
	key *rsa.PublicKey
	exp time.Time
}

var jwksCache struct {
	mu   sync.Mutex
	m    map[string]cachedKey
	ttl  time.Duration
	once sync.Once
}

func jwksCacheInit() {
	jwksCache.once.Do(func() {
		jwksCache.m = make(map[string]cachedKey)
		jwksCache.ttl = getenvDuration("JWKS_CACHE_TTL", 5*time.Minute)
		log.Printf("jwks cache ttl=%s", jwksCache.ttl)
	})
}

func cacheKey(issuer, kid string) string { return issuer + "|" + kid }

func getCachedPublicKey(issuer, kid string) *rsa.PublicKey {
	if issuer == "" || kid == "" {
		return nil
	}
	jwksCacheInit()
	jwksCache.mu.Lock()
	ck, ok := jwksCache.m[cacheKey(issuer, kid)]
	if ok && time.Now().Before(ck.exp) {
		jwksCache.mu.Unlock()
		return ck.key
	}
	jwksCache.mu.Unlock()
	return nil
}

func setCachedPublicKey(issuer, kid string, key *rsa.PublicKey) {
	if issuer == "" || kid == "" || key == nil {
		return
	}
	jwksCacheInit()
	jwksCache.mu.Lock()
	jwksCache.m[cacheKey(issuer, kid)] = cachedKey{key: key, exp: time.Now().Add(jwksCache.ttl)}
	jwksCache.mu.Unlock()
}

func heartbeatHandler(reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

		var body HeartbeatBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid JSON", err)
			return
		}

		senderIP := clientIP(r)
		if senderIP == nil {
			writeAPIError(w, http.StatusBadRequest, "could not determine sender IP", nil)
			return
		}

		if !getHeartbeatLimiter().Allow(senderIP.String()) {
			// Hint clients when to retry; default aligns with expected heartbeat period
			w.Header().Set("Retry-After", "30")
			writeAPIError(w, http.StatusTooManyRequests, "rate limit exceeded", nil)
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
			writeAPIError(w, http.StatusBadRequest, "missing authentication", nil)
			return
		}

		announcedIP := strings.TrimSpace(body.Address)
		if announcedIP == "" {
			announcedIP = senderIP.String()
		}
		body.Address = announcedIP

		keyFunc := func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
			}
			if c, ok := t.Claims.(*HeartbeatClaims); ok {
				issuer := c.RegisteredClaims.Issuer
				if issuer == "" {
					issuer = "http://" + announcedIP + ":" + strconv.Itoa(body.APIPort)
				}
				var kid string
				if hv, ok := t.Header["kid"]; ok {
					if s, ok := hv.(string); ok {
						kid = s
					}
				}
				pk := getCachedPublicKey(issuer, kid)
				if pk == nil {
					pk, err := resolvePublicKey(issuer, kid)
					if err != nil {
						return nil, err
					}
					setCachedPublicKey(issuer, kid, pk)
				}
				return pk, nil
			}
			return nil, errors.New("invalid claims type")
		}

		token, err := jwt.ParseWithClaims(tokenString, &HeartbeatClaims{}, keyFunc, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))
		if err != nil || !token.Valid {
			writeAPIError(w, http.StatusUnauthorized, "invalid token", err)
			return
		}
		claims, ok := token.Claims.(*HeartbeatClaims)
		if !ok {
			writeAPIError(w, http.StatusUnauthorized, "invalid claims", nil)
			return
		}

		if body.Port == 0 {
			writeAPIError(w, http.StatusBadRequest, "port is required", nil)
			return
		}
		serverId := claims.RegisteredClaims.Subject
		if serverId == "" {
			writeAPIError(w, http.StatusBadRequest, "subject is required", nil)
			return
		}

		if existing := reg.Get(serverId); existing != nil {
			if existing.Address != body.Address || existing.Port != body.Port {
				// TODO for verified servers, this will be allowed
				writeAPIError(w, http.StatusBadRequest, "address or port changed for existing ID", nil)
				return
			}
			// Update metadata on heartbeat
			updated := *existing
			updated.Name = body.Name
			updated.CurrentPlayers = body.CurrentPlayers
			updated.MaxPlayers = body.MaxPlayers
			reg.Upsert(updated)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		if body.CurrentPlayers < 0 || body.MaxPlayers < 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid players data", nil)
			return
		}
		if len(body.Name) > 200 {
			writeAPIError(w, http.StatusBadRequest, "invalid name", nil)
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
