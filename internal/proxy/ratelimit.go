package proxy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a deterministic fixed-window limiter keyed by subject and tool.
// It only enforces decisions that already carry the rate_limit obligation.
type RateLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	state  map[string]rateWindow
}

type rateWindow struct {
	start time.Time
	count int
}

// NewRateLimiter validates and constructs a rate limiter.
func NewRateLimiter(limit int, window time.Duration) (*RateLimiter, error) {
	if limit <= 0 {
		return nil, errors.New("rate limit must be positive")
	}
	if window <= 0 {
		return nil, errors.New("rate-limit window must be positive")
	}
	return &RateLimiter{limit: limit, window: window, state: make(map[string]rateWindow)}, nil
}

// ParseRateLimit parses "<count>/<duration>", for example "60/1m".
func ParseRateLimit(value string) (*RateLimiter, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return nil, fmt.Errorf("rate limit %q must use <count>/<duration>, for example 60/1m", value)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("rate limit %q has an invalid count", value)
	}
	window, err := time.ParseDuration(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("rate limit %q has an invalid duration: %w", value, err)
	}
	return NewRateLimiter(limit, window)
}

// Allow consumes one token for key. It returns the remaining budget and the
// instant at which the current fixed window resets.
func (r *RateLimiter) Allow(key string, now time.Time) (bool, int, time.Time) {
	if r == nil {
		return true, 0, time.Time{}
	}
	now = now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.state[key]
	if !exists || now.Before(current.start) || !now.Before(current.start.Add(r.window)) {
		current = rateWindow{start: now}
	}
	reset := current.start.Add(r.window)
	if current.count >= r.limit {
		r.state[key] = current
		return false, 0, reset
	}
	current.count++
	r.state[key] = current
	return true, r.limit - current.count, reset
}

// WaitUntilReset reports the remaining duration in the current window.
func (r *RateLimiter) WaitUntilReset(now time.Time, reset time.Time) time.Duration {
	if reset.IsZero() || !reset.After(now) {
		return 0
	}
	return reset.Sub(now)
}
