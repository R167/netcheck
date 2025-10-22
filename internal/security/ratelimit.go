package security

import (
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens         int
	maxTokens      int
	refillRate     time.Duration
	refillInterval time.Duration
	mu             sync.Mutex
	lastRefill     time.Time
}

// NewRateLimiter creates a new rate limiter
// maxRequests: maximum number of requests allowed
// perDuration: time window for the max requests
func NewRateLimiter(maxRequests int, perDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:         maxRequests,
		maxTokens:      maxRequests,
		refillRate:     perDuration,
		refillInterval: perDuration / time.Duration(maxRequests),
		lastRefill:     time.Now(),
	}
}

// Wait blocks until a token is available, implementing rate limiting
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Refill tokens based on time elapsed
	r.refill()

	// If no tokens available, wait for next refill
	if r.tokens <= 0 {
		waitTime := r.refillInterval
		r.mu.Unlock()
		time.Sleep(waitTime)
		r.mu.Lock()
		r.refill()
	}

	// Consume a token
	if r.tokens > 0 {
		r.tokens--
	}
}

// refill adds tokens based on time elapsed (caller must hold lock)
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill)

	tokensToAdd := int(elapsed / r.refillInterval)
	if tokensToAdd > 0 {
		r.tokens += tokensToAdd
		if r.tokens > r.maxTokens {
			r.tokens = r.maxTokens
		}
		r.lastRefill = now
	}
}

// CredentialTestLimiter creates a rate limiter appropriate for credential testing
// Limits to 1 request per 500ms to avoid triggering brute-force detection
func CredentialTestLimiter() *RateLimiter {
	return NewRateLimiter(2, 1*time.Second) // Max 2 requests per second
}

// PortScanLimiter creates a rate limiter appropriate for port scanning
// Allows faster scanning but still respectful
func PortScanLimiter() *RateLimiter {
	return NewRateLimiter(10, 1*time.Second) // Max 10 ports per second
}
