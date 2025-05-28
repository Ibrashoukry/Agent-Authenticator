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
			agentID := extractAgentID(r)
			if agentID == "" {
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

// Dummy extractor: Replace with JWT/context extraction as needed.
func extractAgentID(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		// TODO: Parse JWT and extract agent ID claim
		return "agent-001" // placeholder
	}
	return ""
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
	path := filepath.Join("..", "..", "configs", "agents.yaml")
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
		m[a.AgentID] = filepath.Join("..", "..", "configs", a.PublicKey)
	}
	return m, nil
}

// JWT Auth middleware: validates JWT and sets agentID in context
func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentKeys, err := loadAgentConfigs()
		if err != nil {
			http.Error(w, "Server config error", http.StatusInternalServerError)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		// Parse JWT to get agentID (sub claim)
		agentID, err := auth.ExtractAgentIDFromJWT(tokenString, agentKeys)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		// Set agentID in context for downstream use
		r = r.WithContext(auth.WithAgentID(r.Context(), agentID))
		next.ServeHTTP(w, r)
	})
}

// Logging and anomaly detection middleware
func LoggingAndAnomalyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		agentID, _ := auth.GetAgentID(r.Context())
		// Log request
		log.Printf("agent=%s method=%s path=%s remote=%s", agentID, r.Method, r.URL.Path, r.RemoteAddr)
		// Simple anomaly detection: log if request is too fast (e.g., <100ms since last)
		isAnomaly, delta := isAnomalous(agentID)
		if isAnomaly {
			log.Printf("ANOMALY: agent=%s rapid requests (delta=%.2fms)", agentID, delta.Seconds()*1000)
		}
		// Update dashboard stats
		monitor.UpdateAgentStatus(agentID, time.Now(), isAnomaly)
		next.ServeHTTP(w, r)
		log.Printf("agent=%s status=done duration=%s", agentID, time.Since(start))
	})
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
	if delta < 100*time.Millisecond {
		return true, delta
	}
	return false, delta
}
