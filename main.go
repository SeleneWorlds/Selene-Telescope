package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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

type HeartbeatRequest struct {
	ID             string `json:"id"`
	Address        string `json:"address,omitempty"`
	Port           int    `json:"port"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
	Name           string `json:"name,omitempty"`
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
		var hb HeartbeatRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&hb); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		senderIP := clientIP(r)
		if senderIP == nil {
			http.Error(w, "could not determine sender IP", http.StatusBadRequest)
			return
		}
		hb.Address = senderIP.String()
		if hb.Port == 0 {
			http.Error(w, "port is required", http.StatusBadRequest)
			return
		}
		if hb.Address == "" {
			http.Error(w, "address is required and could not be inferred", http.StatusBadRequest)
			return
		}
		lookupID := hb.ID
		if lookupID == "" {
			lookupID = hb.Address + ":" + strconv.Itoa(hb.Port)
		}

		if existing := reg.Get(lookupID); existing != nil {
			if existing.Address != hb.Address || existing.Port != hb.Port {
				http.Error(w, "address or port changed for existing ID", http.StatusBadRequest)
				return
			}
			reg.Touch(lookupID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		if hb.CurrentPlayers < 0 || hb.MaxPlayers < 0 || hb.CurrentPlayers > hb.MaxPlayers {
			http.Error(w, "invalid players data", http.StatusBadRequest)
			return
		}
		if len(hb.Name) > 200 {
			http.Error(w, "name too long", http.StatusBadRequest)
			return
		}

		s := ServerInfo{
			ID:             hb.ID,
			Name:           hb.Name,
			Address:        hb.Address,
			Port:           hb.Port,
			CurrentPlayers: hb.CurrentPlayers,
			MaxPlayers:     hb.MaxPlayers,
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
