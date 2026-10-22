package security

import (
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

func TestBruteForceLimiter_BelowThresholdNotBlocked(t *testing.T) {
	l, _ := newTestLimiter()
	if l.Fail("1.1.1.1") || l.Fail("1.1.1.1") {
		t.Fatal("expected no block below threshold")
	}
	if blocked, _ := l.Blocked("1.1.1.1"); blocked {
		t.Error("expected not blocked")
	}
}

func TestBruteForceLimiter_ThresholdBlocks(t *testing.T) {
	l, _ := newTestLimiter()
	l.Fail("1.1.1.1")
	l.Fail("1.1.1.1")
	if !l.Fail("1.1.1.1") {
		t.Fatal("expected third failure to block")
	}
	blocked, remaining := l.Blocked("1.1.1.1")
	if !blocked || remaining != 10*time.Minute {
		t.Errorf("expected blocked for 10m, got blocked=%v remaining=%s", blocked, remaining)
	}
	if blocked, _ := l.Blocked("2.2.2.2"); blocked {
		t.Error("expected other IPs to be unaffected")
	}
}

func TestBruteForceLimiter_BlockExpires(t *testing.T) {
	l, clock := newTestLimiter()
	for i := 0; i < 3; i++ {
		l.Fail("1.1.1.1")
	}
	clock.t = clock.t.Add(10*time.Minute + time.Second)
	if blocked, _ := l.Blocked("1.1.1.1"); blocked {
		t.Fatal("expected block to have expired")
	}
	if l.Fail("1.1.1.1") {
		t.Error("expected counter to start fresh after block expiry")
	}
}

func TestBruteForceLimiter_WindowExpiryForgetsFailures(t *testing.T) {
	l, clock := newTestLimiter()
	l.Fail("1.1.1.1")
	l.Fail("1.1.1.1")
	clock.t = clock.t.Add(61 * time.Second)
	if l.Fail("1.1.1.1") {
		t.Error("expected failures outside the window to be forgotten")
	}
}

func TestBruteForceLimiter_Reset(t *testing.T) {
	l, _ := newTestLimiter()
	l.Fail("1.1.1.1")
	l.Fail("1.1.1.1")
	l.Reset("1.1.1.1")
	l.Fail("1.1.1.1")
	if l.Fail("1.1.1.1") {
		t.Error("expected reset to clear failures")
	}
}

func TestBruteForceLimiter_CapacityEvictsOldestUnblocked(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxEntries = 3
	for i := 0; i < 3; i++ {
		l.Fail("a")
	}
	clock.t = clock.t.Add(time.Second)
	l.Fail("b")
	clock.t = clock.t.Add(time.Second)
	l.Fail("c")
	clock.t = clock.t.Add(time.Second)
	l.Fail("d")
	if len(l.entries) > 3 {
		t.Fatalf("expected at most 3 entries, got %d", len(l.entries))
	}
	if blocked, _ := l.Blocked("a"); !blocked {
		t.Error("expected blocked entry to survive eviction")
	}
	if _, exists := l.entries["b"]; exists {
		t.Error("expected oldest unblocked entry 'b' to be evicted")
	}
}
