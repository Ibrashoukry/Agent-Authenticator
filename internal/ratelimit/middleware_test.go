package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Dummy RateLimiter for testing
// Allows only 2 requests per agent per second
func newTestRateLimiter() RateLimiter {
	return NewInMemoryRateLimiter(2, time.Second)
}

func TestRateLimitMiddleware_AllowsWithinLimit(t *testing.T) {
	rl := newTestRateLimiter()
	mw := RateLimitMiddleware(rl)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/agent", nil)
	req.Header.Set("Authorization", "Bearer dummy")

	for i := 0; i < 2; i++ {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		if rw.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rw.Code)
		}
	}
}

func TestRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	rl := newTestRateLimiter()
	mw := RateLimitMiddleware(rl)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/agent", nil)
	req.Header.Set("Authorization", "Bearer dummy")

	// Hit the limit
	for i := 0; i < 2; i++ {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
	}
	// This one should be blocked
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", rw.Code)
	}
}

func TestRateLimitMiddleware_MissingAgentID(t *testing.T) {
	rl := newTestRateLimiter()
	mw := RateLimitMiddleware(rl)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/agent", nil)
	// No Authorization header
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rw.Code)
	}
}

// Agent struct for YAML parsing
type Agent struct {
	AgentID      string  `yaml:"AgentID"`
	PublicKey    string  `yaml:"PublicKey"`
	Registered   string  `yaml:"Registered"`
	LastActive   string  `yaml:"LastActive"`
	RateLimit    int     `yaml:"RateLimit"`
	AnomalyScore float64 `yaml:"AnomalyScore"`
}

type agentList struct {
	Agents []Agent `yaml:"agents"`
}

// Helper to load agents from YAML
func loadTestAgents(t *testing.T) []Agent {
	f, err := os.Open("../../configs/agents.yaml")
	if err != nil {
		t.Fatalf("failed to open agents.yaml: %v", err)
	}
	defer f.Close()
	var list agentList
	if err := yaml.NewDecoder(f).Decode(&list); err != nil {
		t.Fatalf("failed to decode agents.yaml: %v", err)
	}
	return list.Agents
}

func TestRateLimitMiddleware_UsesYamlAgents(t *testing.T) {
	agents := loadTestAgents(t)
	if len(agents) == 0 {
		t.Fatal("no agents loaded from YAML")
	}
	// Use the first agent for testing
	rl := NewInMemoryRateLimiter(2, time.Second)
	mw := RateLimitMiddleware(rl)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/agent", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", agents[0].AgentID))

	for i := 0; i < 2; i++ {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		if rw.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rw.Code)
		}
	}
	// Third request should be blocked
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", rw.Code)
	}
}
