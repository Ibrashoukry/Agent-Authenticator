package main

import (
	"log"
	"net/http"
	"time"

	"agent-auth/internal/auth"
	"agent-auth/internal/monitor"
	"agent-auth/internal/ratelimit"
)

func withMiddlewares(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

func main() {
	// TODO: Load configuration (keys, rate limits, etc.)

	// TODO: Initialize storage (PostgreSQL/Redis) for tokens, keys, rate limits

	// TODO: Initialize authentication module (RSA/HMAC, JWT, token rotation)

	// TODO: Initialize rate limiting and anomaly detection

	// TODO: Initialize monitoring/metrics

	// Initialize rate limiter (e.g., 10 requests per minute per agent)
	rl := ratelimit.NewInMemoryRateLimiter(10, time.Minute)

	mux := http.NewServeMux()

	// Serve static dashboard files only at /dashboard/
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard/", http.FileServer(http.Dir("web/dashboard"))))
	// Redirect base URL / to /dashboard/ only if path is exactly "/"
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/dashboard/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	// Agent registration endpoint (no rate limit)
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement agent registration and RSA key management
		w.Write([]byte("Agent registration endpoint"))
	})

	// Authenticated agent endpoint (with JWT, rate limiting, logging/anomaly)
	agentHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := auth.GetAgentID(r.Context())
		log.Printf("[agentHandler] agentID from context: '%s' (ok=%v)", agentID, ok)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing agent ID in context"))
			return
		}
		w.Write([]byte("Authenticated agent: " + agentID))
	})
	mux.Handle("/agent", withMiddlewares(
		agentHandler,
		ratelimit.JWTAuthMiddleware,
		ratelimit.RateLimitMiddleware(rl),
		ratelimit.LoggingAndAnomalyMiddleware,
	))

	// Monitoring endpoint (returns dashboard JSON)
	mux.HandleFunc("/monitor", monitor.DashboardHandler)

	// TODO: Add middleware for logging, anomaly detection, etc.

	addr := ":8080"
	log.Printf("Starting server on %s...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
