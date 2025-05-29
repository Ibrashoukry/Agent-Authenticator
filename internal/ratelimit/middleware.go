package ratelimit

import (
	"agent-auth/internal/auth"
	"agent-auth/internal/monitor"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Example interface for a rate limiter (to be implemented in ratelimiter.go)
type RateLimiter interface {
	Allow(agentID string) bool
}

// Middleware constructor. Pass your RateLimiter implementation.
func RateLimitMiddleware(rl RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[RateLimitMiddleware] called")
			agentID, ok := auth.GetAgentID(r.Context())
			if !ok || agentID == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing or invalid agent ID"))
				return
			}
			if !rl.Allow(agentID) {
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Rate limit exceeded"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type agentConfig struct {
	AgentID      string  `yaml:"AgentID"`
	PublicKey    string  `yaml:"PublicKey"`
	Registered   string  `yaml:"Registered"`
	LastActive   string  `yaml:"LastActive"`
	RateLimit    int     `yaml:"RateLimit"`
	AnomalyScore float64 `yaml:"AnomalyScore"`
}
type agentConfigList struct {
	Agents []agentConfig `yaml:"agents"`
}

// Loads agent configs from YAML for JWT validation
func loadAgentConfigs() (map[string]string, error) {
	path := "configs/agents.yaml"
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var list agentConfigList
	if err := yaml.NewDecoder(f).Decode(&list); err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, a := range list.Agents {
		m[a.AgentID] = filepath.Join("configs", a.PublicKey)
	}
	return m, nil
}

// JWT Auth middleware: validates JWT and sets agentID in context
func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[JWTAuthMiddleware] called")
		agentKeys, err := loadAgentConfigs()
		if err != nil {
			log.Printf("[JWTAuthMiddleware] Server config error: %v", err)
			http.Error(w, "Server config error", http.StatusInternalServerError)
			return
		}
		authHeader := r.Header.Get("Authorization")
		log.Printf("[JWTAuthMiddleware] Authorization header: '%s'", authHeader)
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Printf("[JWTAuthMiddleware] Missing Bearer token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		// Parse JWT to get agentID (sub claim)
		agentID, err := auth.ExtractAgentIDFromJWT(tokenString, agentKeys)
		if err != nil {
			log.Printf("[JWTAuthMiddleware] Invalid token: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		log.Printf("[JWTAuthMiddleware] Extracted agentID: '%s'", agentID)
		// Set agentID in context for downstream use
		r = r.WithContext(auth.WithAgentID(r.Context(), agentID))
		next.ServeHTTP(w, r)
	})
}

// Logging and anomaly detection middleware
func LoggingAndAnomalyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[LoggingAndAnomalyMiddleware] called")
		start := time.Now()
		tags := []string{}
		agentID, _ := auth.GetAgentID(r.Context())
		// Log request
		log.Printf("agent=%s method=%s path=%s remote=%s", agentID, r.Method, r.URL.Path, r.RemoteAddr)
		// Rapid requests anomaly
		isRapid, delta := isAnomalous(agentID)
		if isRapid {
			log.Printf("ANOMALY: agent=%s rapid requests (delta=%.2fms)", agentID, delta.Seconds()*1000)
			tags = append(tags, "Rapid requests")
		}
		// Frequent rate limit violations (simulate: if last 3 requests < 1s apart)
		if checkFrequentRateLimit(agentID) {
			tags = append(tags, "Frequent rate limit violations")
		}
		// Request spike detected (simulate: if 5+ requests in last 2s)
		if checkRequestSpike(agentID) {
			tags = append(tags, "Request spike detected")
		}
		// Repeated auth failures (simulate: if 3+ failures in last 1m)
		if checkAuthFailures(agentID) {
			tags = append(tags, "Repeated auth failures")
		}
		// Multiple IPs detected (simulate: if agentID seen from 2+ IPs in last 1m)
		if checkMultipleIPs(agentID, r.RemoteAddr) {
			tags = append(tags, "Multiple IPs detected")
		}
		// Suspicious payload (simulate: POST with unexpected data)
		if r.Method == "POST" && r.Header.Get("Content-Type") == "application/json" {
			tags = append(tags, "Suspicious payload")
		}
		// Inactivity burst anomaly (simulate: if >3min inactive, then 2+ requests in 10s)
		if checkInactivityBurst(agentID) {
			tags = append(tags, "Inactivity burst anomaly")
		}
		// Update dashboard stats
		monitor.UpdateAgentStatus(agentID, time.Now(), tags)
		next.ServeHTTP(w, r)
		log.Printf("agent=%s status=done duration=%s", agentID, time.Since(start))
	})
}

// --- Simulated anomaly checkers (stub logic, replace with real logic as needed) ---
var (
	lastRequestTimes = make(map[string][]time.Time) // for spike/frequency
	authFailures     = make(map[string][]time.Time)
	agentIPs         = make(map[string]map[string]time.Time)
)

func checkFrequentRateLimit(agentID string) bool {
	times := lastRequestTimes[agentID]
	if len(times) < 3 {
		return false
	}
	return times[len(times)-1].Sub(times[len(times)-3]) < time.Second
}

func checkRequestSpike(agentID string) bool {
	times := lastRequestTimes[agentID]
	now := time.Now()
	count := 0
	for i := len(times) - 1; i >= 0; i-- {
		if now.Sub(times[i]) < 2*time.Second {
			count++
		}
	}
	return count >= 5
}

func checkAuthFailures(agentID string) bool {
	failures := authFailures[agentID]
	now := time.Now()
	count := 0
	for i := len(failures) - 1; i >= 0; i-- {
		if now.Sub(failures[i]) < time.Minute {
			count++
		}
	}
	return count >= 3
}

func checkMultipleIPs(agentID, ip string) bool {
	if agentIPs[agentID] == nil {
		agentIPs[agentID] = make(map[string]time.Time)
	}
	agentIPs[agentID][ip] = time.Now()
	count := 0
	now := time.Now()
	for _, t := range agentIPs[agentID] {
		if now.Sub(t) < time.Minute {
			count++
		}
	}
	return count >= 2
}

func checkInactivityBurst(agentID string) bool {
	times := lastRequestTimes[agentID]
	if len(times) < 2 {
		return false
	}
	if times[len(times)-2].Add(3 * time.Minute).Before(times[len(times)-1]) {
		return true
	}
	return false
}

// Simple in-memory last request time for anomaly detection
var lastRequestTime = make(map[string]time.Time)

func isAnomalous(agentID string) (bool, time.Duration) {
	now := time.Now()
	last, ok := lastRequestTime[agentID]
	lastRequestTime[agentID] = now
	if !ok {
		return false, 0
	}
	delta := now.Sub(last)
	// Track for spike/frequency
	lastRequestTimes[agentID] = append(lastRequestTimes[agentID], now)
	if len(lastRequestTimes[agentID]) > 10 {
		lastRequestTimes[agentID] = lastRequestTimes[agentID][1:]
	}
	return delta < 100*time.Millisecond, delta
}
