package ratelimit

import (
	"sync"
	"time"
)

// Simple in-memory token bucket rate limiter per agent
// For production, consider Redis or distributed store

type tokenBucket struct {
	capacity   int
	tokens     int
	lastRefill time.Time
	interval   time.Duration
}

type InMemoryRateLimiter struct {
	buckets  map[string]*tokenBucket
	mu       sync.Mutex
	capacity int
	interval time.Duration
}

// NewInMemoryRateLimiter creates a new rate limiter
func NewInMemoryRateLimiter(capacity int, interval time.Duration) *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		buckets:  make(map[string]*tokenBucket),
		capacity: capacity,
		interval: interval,
	}
}

// Allow checks if the agent can proceed
func (rl *InMemoryRateLimiter) Allow(agentID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	bucket, exists := rl.buckets[agentID]
	if !exists {
		bucket = &tokenBucket{
			capacity:   rl.capacity,
			tokens:     rl.capacity - 1,
			lastRefill: time.Now(),
			interval:   rl.interval,
		}
		rl.buckets[agentID] = bucket
		return true
	}
	// refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	if elapsed > bucket.interval {
		bucket.tokens = bucket.capacity - 1
		bucket.lastRefill = now
		return true
	}
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	return false
}
