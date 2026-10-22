package security

import (
	"net"
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

// Attempt counts a login attempt from ip before its credentials are checked, so concurrent requests cannot
// exceed the cap. It returns whether the attempt may proceed; when it may not, retryAfter is the remaining block time.
// blockedNow is true only for the attempt that started the block. A successful login must call Reset.
func (l *bruteForceLimiter) Attempt(ip string) (allowed bool, retryAfter time.Duration, blockedNow bool) {
	key := limiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.entries[key]
	if !exists {
		l.makeRoom(now)
		entry = &bruteForceEntry{windowStart: now}
		l.entries[key] = entry
	}
	entry.lastSeen = now
	if remaining := entry.blockedUntil.Sub(now); remaining > 0 {
		return false, remaining, false
	}
	if !entry.blockedUntil.IsZero() || entry.failures == 0 || now.Sub(entry.windowStart) > l.window {
		entry.blockedUntil = time.Time{}
		entry.failures = 0
		entry.windowStart = now
	}
	entry.failures++
	if entry.failures > l.maxAttempts {
		entry.blockedUntil = now.Add(l.blockDuration)
		entry.failures = 0
		return false, l.blockDuration, true
	}
	return true, 0, false
}

// Reset forgets everything known about ip
func (l *bruteForceLimiter) Reset(ip string) {
	key := limiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// limiterKey maps a client IP to the key it is limited under: IPv4 (including IPv4-mapped) addresses are kept,
// IPv6 addresses are collapsed to their /64 network, and unparseable input is returned unchanged
func limiterKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	mask := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: parsed.Mask(mask), Mask: mask}).String()
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
