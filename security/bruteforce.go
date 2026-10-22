package security

import (
	"sync"
	"time"
)

const defaultMaxTrackedIPs = 10000

// limiter is the package-level limiter; it survives configuration hot reloads
var limiter = newBruteForceLimiter(time.Now)

type bruteForceEntry struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

// bruteForceLimiter tracks failed login attempts per IP and blocks IPs that fail too often
type bruteForceLimiter struct {
	mu            sync.Mutex
	now           func() time.Time
	maxAttempts   int
	window        time.Duration
	blockDuration time.Duration
	maxEntries    int
	entries       map[string]*bruteForceEntry
}

func newBruteForceLimiter(now func() time.Time) *bruteForceLimiter {
	return &bruteForceLimiter{
		now:           now,
		maxAttempts:   DefaultBruteForceMaxAttempts,
		window:        DefaultBruteForceWindow,
		blockDuration: DefaultBruteForceBlockDuration,
		maxEntries:    defaultMaxTrackedIPs,
		entries:       make(map[string]*bruteForceEntry),
	}
}

// configure copies the thresholds from cfg, keeping existing entries
func (l *bruteForceLimiter) configure(cfg *BruteForceConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxAttempts = cfg.MaxAttempts
	l.window = cfg.Window
	l.blockDuration = cfg.BlockDuration
}

// Fail records a failed attempt for ip and returns whether this attempt caused the IP to become blocked
func (l *bruteForceLimiter) Fail(ip string) (blockedNow bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.entries[ip]
	if !exists {
		l.makeRoom(now)
		entry = &bruteForceEntry{windowStart: now}
		l.entries[ip] = entry
	}
	entry.lastSeen = now
	if now.Before(entry.blockedUntil) {
		return false
	}
	if entry.failures == 0 || now.Sub(entry.windowStart) > l.window {
		entry.failures = 0
		entry.windowStart = now
	}
	entry.failures++
	if entry.failures >= l.maxAttempts {
		entry.blockedUntil = now.Add(l.blockDuration)
		entry.failures = 0
		return true
	}
	return false
}

// Blocked returns whether ip is currently blocked and, if so, for how much longer
func (l *bruteForceLimiter) Blocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.entries[ip]
	if !exists {
		return false, 0
	}
	if remaining := entry.blockedUntil.Sub(l.now()); remaining > 0 {
		return true, remaining
	}
	return false, 0
}

// Reset forgets everything known about ip
func (l *bruteForceLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// makeRoom frees a slot for a new entry when the table is full. The caller must hold l.mu.
func (l *bruteForceLimiter) makeRoom(now time.Time) {
	if len(l.entries) < l.maxEntries {
		return
	}
	for key, e := range l.entries {
		if !now.Before(e.blockedUntil) && now.Sub(e.windowStart) > l.window {
			delete(l.entries, key)
		}
	}
	for len(l.entries) >= l.maxEntries {
		var oldestKey string
		var oldest time.Time
		found, foundUnblocked := false, false
		for key, e := range l.entries {
			unblocked := !now.Before(e.blockedUntil)
			if found && foundUnblocked && !unblocked {
				continue
			}
			if !found || (unblocked && !foundUnblocked) || e.lastSeen.Before(oldest) {
				oldestKey, oldest, found, foundUnblocked = key, e.lastSeen, true, unblocked
			}
		}
		if !found {
			return
		}
		delete(l.entries, oldestKey)
	}
}
