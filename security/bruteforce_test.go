package security

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func newTestLimiter() (*bruteForceLimiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)}
	l := newBruteForceLimiter(clock.now)
	l.configure(&BruteForceConfig{MaxAttempts: 3, Window: time.Minute, BlockDuration: 10 * time.Minute})
	return l, clock
}

func attempts(l *bruteForceLimiter, ip string, n int) {
	for i := 0; i < n; i++ {
		l.Attempt(ip)
	}
}

func TestBruteForceLimiter_BelowThresholdAllowed(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 3; i++ {
		if allowed, _, _ := l.Attempt("1.1.1.1"); !allowed {
			t.Fatalf("expected attempt %d to be allowed", i+1)
		}
	}
}

func TestBruteForceLimiter_ThresholdBlocks(t *testing.T) {
	l, _ := newTestLimiter()
	attempts(l, "1.1.1.1", 3)
	allowed, retryAfter, blockedNow := l.Attempt("1.1.1.1")
	if allowed || retryAfter != 10*time.Minute || !blockedNow {
		t.Fatalf("4th: expected (false, 10m, true), got (%v, %s, %v)", allowed, retryAfter, blockedNow)
	}
	allowed, retryAfter, blockedNow = l.Attempt("1.1.1.1")
	if allowed || retryAfter != 10*time.Minute || blockedNow {
		t.Fatalf("5th: expected (false, 10m, false), got (%v, %s, %v)", allowed, retryAfter, blockedNow)
	}
	if allowed, _, _ := l.Attempt("2.2.2.2"); !allowed {
		t.Error("expected other IPs to be unaffected")
	}
}

func TestBruteForceLimiter_BlockExpires(t *testing.T) {
	l, clock := newTestLimiter()
	attempts(l, "1.1.1.1", 4)
	clock.t = clock.t.Add(10*time.Minute + time.Second)
	if allowed, _, _ := l.Attempt("1.1.1.1"); !allowed {
		t.Fatal("expected attempt allowed after block expiry")
	}
}

func TestBruteForceLimiter_WindowExpiryForgetsAttempts(t *testing.T) {
	l, clock := newTestLimiter()
	attempts(l, "1.1.1.1", 3)
	clock.t = clock.t.Add(61 * time.Second)
	if allowed, _, _ := l.Attempt("1.1.1.1"); !allowed {
		t.Error("expected attempts outside the window to be forgotten")
	}
}

func TestBruteForceLimiter_Reset(t *testing.T) {
	l, _ := newTestLimiter()
	attempts(l, "1.1.1.1", 3)
	l.Reset("1.1.1.1")
	for i := 0; i < 3; i++ {
		if allowed, _, _ := l.Attempt("1.1.1.1"); !allowed {
			t.Fatalf("expected attempt %d after reset to be allowed", i+1)
		}
	}
}

func TestBruteForceLimiter_CapacityEvictsOldestUnblocked(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxEntries = 3
	attempts(l, "a", 4)
	clock.t = clock.t.Add(time.Second)
	l.Attempt("b")
	clock.t = clock.t.Add(time.Second)
	l.Attempt("c")
	clock.t = clock.t.Add(time.Second)
	l.Attempt("d")
	if len(l.entries) > 3 {
		t.Fatalf("expected at most 3 entries, got %d", len(l.entries))
	}
	if _, exists := l.entries["b"]; exists {
		t.Error("expected oldest unblocked entry 'b' to be evicted")
	}
	if allowed, _, _ := l.Attempt("a"); allowed {
		t.Error("expected blocked entry to survive eviction")
	}
}

func TestBruteForceLimiter_ConcurrentAttemptsCapped(t *testing.T) {
	l, _ := newTestLimiter()
	var allowedCount int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if allowed, _, _ := l.Attempt("1.1.1.1"); allowed {
				atomic.AddInt32(&allowedCount, 1)
			}
		}()
	}
	wg.Wait()
	if allowedCount != 3 {
		t.Errorf("expected exactly 3 allowed attempts, got %d", allowedCount)
	}
}

func TestBruteForceLimiter_IPv6SharesSlash64(t *testing.T) {
	l, _ := newTestLimiter()
	attempts(l, "2001:db8:1:2::1", 3)
	if allowed, _, _ := l.Attempt("2001:db8:1:2::ffff"); allowed {
		t.Error("expected same /64 to share the counter")
	}
	if allowed, _, _ := l.Attempt("2001:db8:1:3::1"); !allowed {
		t.Error("expected a different /64 to be unaffected")
	}
}

func TestLimiterKey(t *testing.T) {
	scenarios := []struct{ Name, IP, Expected string }{
		{"ipv4", "203.0.113.7", "203.0.113.7"},
		{"ipv4-mapped", "::ffff:1.2.3.4", "1.2.3.4"},
		{"ipv6", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"garbage", "garbage", "garbage"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			if actual := limiterKey(scenario.IP); actual != scenario.Expected {
				t.Errorf("expected %s, got %s", scenario.Expected, actual)
			}
		})
	}
}
