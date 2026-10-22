# Login Form + Brute-Force IP Blocking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in username/password form login (instead of the Basic Auth popup) with per-IP brute-force blocking that resolves the client IP from `CF-Connecting-IP` behind Cloudflare, plus a `mise.toml` that builds and pushes `cuongtransc/gatus`.

**Architecture:** `security.basic.login-form: true` registers `POST /login` + `POST /logout`, which create/delete sessions in the existing in-memory `sessions` cache; the protected router uses the same g8 session-cookie gate OIDC already uses. A package-level limiter counts failed logins per client IP; the client IP comes from `CF-Connecting-IP` only when the TCP peer is a Cloudflare range or a configured trusted proxy. The Vue login screen gains a form when `/api/v1/config` reports `loginForm: true`.

**Tech Stack:** Go 1.26, Fiber v2.52, g8 v2, gocache v2, bcrypt; Vue 3 + Tailwind; mise; docker buildx.

**Spec:** `docs/superpowers/specs/2026-10-22-login-form-design.md`

## Global Constraints

- Config keys are kebab-case YAML: `login-form`, `session-ttl`, `brute-force`, `max-attempts`, `window`, `block-duration`, `trusted-proxies`.
- Defaults: `session-ttl` 8h (`DefaultBasicSessionTTL`), `max-attempts` 5, `window` 15m, `block-duration` 30m, max tracked IPs 10 000. A zero value means "use the default"; a negative value is invalid.
- Without `login-form: true` every existing Basic Auth behaviour and test stays unchanged.
- JSON error bodies from `/login` and `/logout` are exactly `{"error":"<message>"}` with `Content-Type: application/json`. Messages: `invalid request` (400), `invalid credentials` (401), `too many failed attempts` (429).
- `Retry-After` is an integer number of seconds, rounded up.
- The client IP for limiting is obtained only through `(*Config).clientIP(ctx)` (Task 2); no code reads `X-Forwarded-For`.
- Log lines follow the existing `logr` format: `[security.<function>] message`.
- `web/static/` is only ever changed by `make frontend-build`; never edited by hand.
- No AI attribution lines in commits (user's global rule overrides AGENTS.md here).
- Tests in `security/` that touch the package-level `limiter` or `sessions` do not call `t.Parallel()`.

## Review Focus

1. A request whose peer is NOT Cloudflare but carries a forged `CF-Connecting-IP` must be limited by the peer IP — Task 2 table case `non-cloudflare-peer-header-ignored`.
2. A correct password from a blocked IP must still get 429 (block checked before credentials) — Task 4 `TestLogin_BlocksAfterMaxAttempts`.
3. Malformed body (`{` or empty) returns 400 and is not counted as a failure — Task 4 `TestLogin_MalformedBodyNotCounted`.
4. Existing Basic Auth mode (no `login-form`) still answers 401 + `WWW-Authenticate: Basic` and accepts the header — existing `TestConfig_ApplySecurityMiddleware/basic` must stay green, run in Task 4.
5. Logged-out session cookie no longer opens protected routes — Task 4 `TestLogout`.

---

### Task 1: Config fields, defaults and validation

**Files:**
- Modify: `security/basic.go`
- Create: `security/bruteforce_config.go`
- Modify: `security/config.go` (`Config` struct, `ValidateAndSetDefaults`)
- Test: `security/config_test.go`

**Interfaces:**
- Produces:
  - `BasicConfig.LoginForm bool` (`yaml:"login-form,omitempty"`), `BasicConfig.SessionTTL time.Duration` (`yaml:"session-ttl,omitempty"`), `const DefaultBasicSessionTTL = 8 * time.Hour`
  - `type BruteForceConfig struct { MaxAttempts int \`yaml:"max-attempts,omitempty"\`; Window time.Duration \`yaml:"window,omitempty"\`; BlockDuration time.Duration \`yaml:"block-duration,omitempty"\`; TrustedProxies []string \`yaml:"trusted-proxies,omitempty"\`; trustedNets []*net.IPNet }`
  - `func (c *BruteForceConfig) ValidateAndSetDefaults() bool`
  - `Config.BruteForce *BruteForceConfig` (`yaml:"brute-force,omitempty"`)
  - Constants `DefaultBruteForceMaxAttempts = 5`, `DefaultBruteForceWindow = 15 * time.Minute`, `DefaultBruteForceBlockDuration = 30 * time.Minute`

- [ ] **Step 1: Write the failing tests** (append to `security/config_test.go`; add `"time"` to imports)

```go
func TestConfig_ValidateAndSetDefaults_LoginForm(t *testing.T) {
	c := &Config{Basic: &BasicConfig{
		Username:                        "test",
		PasswordBcryptHashBase64Encoded: "somevalue",
		LoginForm:                       true,
	}}
	if !c.ValidateAndSetDefaults() {
		t.Fatal("expected config to be valid")
	}
	if c.Basic.SessionTTL != DefaultBasicSessionTTL {
		t.Errorf("expected session TTL %s, got %s", DefaultBasicSessionTTL, c.Basic.SessionTTL)
	}
	if c.BruteForce == nil {
		t.Fatal("expected brute-force defaults to be set when login-form is enabled")
	}
	if c.BruteForce.MaxAttempts != 5 || c.BruteForce.Window != 15*time.Minute || c.BruteForce.BlockDuration != 30*time.Minute {
		t.Errorf("unexpected brute-force defaults: %+v", c.BruteForce)
	}
}

func TestConfig_ValidateAndSetDefaults_BasicWithoutLoginFormKeepsBruteForceNil(t *testing.T) {
	c := &Config{Basic: &BasicConfig{Username: "test", PasswordBcryptHashBase64Encoded: "somevalue"}}
	if !c.ValidateAndSetDefaults() {
		t.Fatal("expected config to be valid")
	}
	if c.BruteForce != nil {
		t.Error("expected brute-force to stay nil without login-form")
	}
}

func TestBruteForceConfig_ValidateAndSetDefaults(t *testing.T) {
	scenarios := []struct {
		Name            string
		Config          *BruteForceConfig
		ExpectValid     bool
		ExpectedNetsLen int
	}{
		{Name: "zero-values-get-defaults", Config: &BruteForceConfig{}, ExpectValid: true},
		{Name: "negative-max-attempts", Config: &BruteForceConfig{MaxAttempts: -1}, ExpectValid: false},
		{Name: "negative-window", Config: &BruteForceConfig{Window: -time.Second}, ExpectValid: false},
		{Name: "negative-block-duration", Config: &BruteForceConfig{BlockDuration: -time.Second}, ExpectValid: false},
		{Name: "valid-trusted-proxies", Config: &BruteForceConfig{TrustedProxies: []string{"10.0.0.0/8", "192.168.1.5", "2001:db8::/32", "::1"}}, ExpectValid: true, ExpectedNetsLen: 4},
		{Name: "invalid-trusted-proxy", Config: &BruteForceConfig{TrustedProxies: []string{"not-an-ip"}}, ExpectValid: false},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			isValid := scenario.Config.ValidateAndSetDefaults()
			if isValid != scenario.ExpectValid {
				t.Fatalf("expected valid=%v, got %v", scenario.ExpectValid, isValid)
			}
			if !isValid {
				return
			}
			if scenario.Config.MaxAttempts < 1 || scenario.Config.Window <= 0 || scenario.Config.BlockDuration <= 0 {
				t.Errorf("expected defaults to be set, got %+v", scenario.Config)
			}
			if len(scenario.Config.trustedNets) != scenario.ExpectedNetsLen {
				t.Errorf("expected %d trusted nets, got %d", scenario.ExpectedNetsLen, len(scenario.Config.trustedNets))
			}
		})
	}
}
```

Also add one scenario to the existing `TestConfig_ValidateAndSetDefaults` table:

```go
		{
			Name: "invalid-brute-force",
			Config: &Config{
				Basic:      validBasicConfig,
				BruteForce: &BruteForceConfig{MaxAttempts: -1},
			},
			ExpectValid: false,
		},
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./security/ -run 'TestConfig_ValidateAndSetDefaults|TestBruteForceConfig' -v`
Expected: build failure — `unknown field LoginForm`, `undefined: BruteForceConfig`.

- [ ] **Step 3: Implement**

- `security/basic.go`: add the two fields and `DefaultBasicSessionTTL`.
- `security/bruteforce_config.go`: the struct, default constants, and `ValidateAndSetDefaults`: negative values → false; zero → default; each `TrustedProxies` entry parsed with `net.ParseCIDR`, or, if that fails, `net.ParseIP` turned into a /32 (IPv4) or /128 (IPv6) net; neither → false. Rebuild `trustedNets` from scratch on every call (hot reload).
- `security/config.go`: add `BruteForce` field. `ValidateAndSetDefaults`: keep the existing Basic/OIDC checks; then if `Basic != nil && Basic.LoginForm`: set `SessionTTL` default when `<= 0`, and create `&BruteForceConfig{}` when nil; then if `BruteForce != nil` return `BruteForce.ValidateAndSetDefaults()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./security/ -v`
Expected: PASS (all, including pre-existing tests).

- [ ] **Step 5: Commit**

```bash
git add security/basic.go security/bruteforce_config.go security/config.go security/config_test.go
git commit -m "feat(security): add login-form and brute-force configuration"
```

---

### Task 2: Client IP resolution behind Cloudflare

**Files:**
- Create: `security/clientip.go`
- Test: `security/clientip_test.go`

**Interfaces:**
- Consumes: `BruteForceConfig.trustedNets` (Task 1).
- Produces:
  - `func resolveClientIP(peer net.IP, cfConnectingIP string, trusted []*net.IPNet) string`
  - `func isTrustedProxy(peer net.IP, trusted []*net.IPNet) bool` — true if `peer` ∈ Cloudflare ranges or `trusted`
  - `func (c *Config) clientIP(ctx *fiber.Ctx) string` — `resolveClientIP(ctx.Context().RemoteIP(), ctx.Get("CF-Connecting-IP"), c.trustedNets())`
  - `func (c *Config) trustedNets() []*net.IPNet` — `nil` when `c.BruteForce == nil`

- [ ] **Step 1: Write the failing test** (`security/clientip_test.go`)

```go
package security

import (
	"net"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	_, internal, _ := net.ParseCIDR("10.0.0.0/8")
	scenarios := []struct {
		Name     string
		Peer     string
		Header   string
		Trusted  []*net.IPNet
		Expected string
	}{
		{Name: "cloudflare-peer-valid-header", Peer: "173.245.48.1", Header: "203.0.113.7", Expected: "203.0.113.7"},
		{Name: "cloudflare-peer-header-with-spaces", Peer: "104.16.0.1", Header: " 203.0.113.7 ", Expected: "203.0.113.7"},
		{Name: "cloudflare-peer-garbage-header", Peer: "173.245.48.1", Header: "garbage", Expected: "173.245.48.1"},
		{Name: "cloudflare-peer-no-header", Peer: "173.245.48.1", Header: "", Expected: "173.245.48.1"},
		{Name: "non-cloudflare-peer-header-ignored", Peer: "203.0.113.9", Header: "198.51.100.1", Expected: "203.0.113.9"},
		{Name: "trusted-proxy-peer", Peer: "10.1.2.3", Header: "198.51.100.1", Trusted: []*net.IPNet{internal}, Expected: "198.51.100.1"},
		{Name: "untrusted-private-peer", Peer: "10.1.2.3", Header: "198.51.100.1", Expected: "10.1.2.3"},
		{Name: "cloudflare-ipv6-peer", Peer: "2606:4700::1", Header: "2001:db8::1", Expected: "2001:db8::1"},
		{Name: "ipv4-mapped-cloudflare-peer", Peer: "::ffff:173.245.48.1", Header: "203.0.113.7", Expected: "203.0.113.7"},
		{Name: "header-normalised", Peer: "173.245.48.1", Header: "2001:DB8:0:0::1", Expected: "2001:db8::1"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			actual := resolveClientIP(net.ParseIP(scenario.Peer), scenario.Header, scenario.Trusted)
			if actual != scenario.Expected {
				t.Errorf("expected %s, got %s", scenario.Expected, actual)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./security/ -run TestResolveClientIP -v`
Expected: build failure — `undefined: resolveClientIP`.

- [ ] **Step 3: Implement `security/clientip.go`**

Package-level `cloudflareNets` parsed once from this list (comment: source `https://www.cloudflare.com/ips/`, refresh by hand):
IPv4 `173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22`;
IPv6 `2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`.
`resolveClientIP`: if `isTrustedProxy(peer, trusted)` and `net.ParseIP(strings.TrimSpace(header))` is non-nil → return its `.String()`; otherwise return `peer.String()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./security/ -run TestResolveClientIP -v`
Expected: PASS (10 subtests).

- [ ] **Step 5: Commit**

```bash
git add security/clientip.go security/clientip_test.go
git commit -m "feat(security): resolve client IP from CF-Connecting-IP for trusted peers"
```

---

### Task 3: Brute-force limiter

**Files:**
- Create: `security/bruteforce.go`
- Test: `security/bruteforce_test.go`

**Interfaces:**
- Consumes: `BruteForceConfig` (Task 1).
- Produces:
  - `func newBruteForceLimiter(now func() time.Time) *bruteForceLimiter` (maxEntries = `defaultMaxTrackedIPs` = 10000)
  - `func (l *bruteForceLimiter) configure(cfg *BruteForceConfig)` — copies values; keeps existing entries
  - `func (l *bruteForceLimiter) Fail(ip string) (blockedNow bool)`
  - `func (l *bruteForceLimiter) Blocked(ip string) (bool, time.Duration)` — remaining block time
  - `func (l *bruteForceLimiter) Reset(ip string)`
  - `var limiter = newBruteForceLimiter(time.Now)` (package-level, survives hot reload)
  - Fields used by tests: `maxEntries int`, `entries map[string]*bruteForceEntry`

- [ ] **Step 1: Write the failing test** (`security/bruteforce_test.go`)

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./security/ -run TestBruteForceLimiter -v`
Expected: build failure — `undefined: newBruteForceLimiter`.

- [ ] **Step 3: Implement `security/bruteforce.go`**

`bruteForceEntry{failures int; windowStart, blockedUntil, lastSeen time.Time}`; all methods under one `sync.Mutex`. Fixed window starting at the first failure: a failure after `windowStart+Window` restarts the count at 1. Reaching `MaxAttempts` sets `blockedUntil = now+BlockDuration`, zeroes `failures`, returns true. An entry whose block has passed is treated as fresh. Pruning happens only on insert (no background sweep goroutine, deliberately simpler than the spec's "periodic sweep"). Before inserting a new IP when `len(entries) >= maxEntries`: delete entries that are neither blocked nor inside their window; if still full, delete the non-blocked entry with the oldest `lastSeen`; if all are blocked, delete the one with the oldest `lastSeen`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./security/ -run TestBruteForceLimiter -v -race`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add security/bruteforce.go security/bruteforce_test.go
git commit -m "feat(security): add per-IP brute-force limiter"
```

---

### Task 4: Login/logout handlers and session gate

**Files:**
- Create: `security/login.go`
- Modify: `security/config.go` (`RegisterHandlers`, `ApplySecurityMiddleware`)
- Modify: `security/basic.go` (`decodedPasswordHash`)
- Test: `security/login_test.go`

**Interfaces:**
- Consumes: Task 1 fields, `(*Config).clientIP`, `isTrustedProxy` (Task 2), `limiter` (Task 3), existing `sessions`, `cookieNameSession`.
- Produces:
  - Routes `POST /login`, `POST /logout` registered by `RegisterHandlers` when `Basic != nil && Basic.LoginForm`; `RegisterHandlers` also calls `limiter.configure(c.BruteForce)`.
  - `func (c *Config) loginHandler(ctx *fiber.Ctx) error`, `func (c *Config) logoutHandler(ctx *fiber.Ctx) error`
  - `func (c *Config) usesSessions() bool` — `c.OIDC != nil || (c.Basic != nil && c.Basic.LoginForm)`
  - `func (c *BasicConfig) decodedPasswordHash() ([]byte, error)` — base64.URLEncoding decode, shared with the Basic Auth branch

- [ ] **Step 1: Write the failing test** (`security/login_test.go`)

```go
package security

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// bcrypt hash of "hunter2", base64 encoded
const hunter2BcryptB64 = "JDJhJDA4JDFoRnpPY1hnaFl1OC9ISlFsa21VS09wOGlPU1ZOTDlHZG1qeTFvb3dIckRBUnlHUmNIRWlT"

func newLoginFormApp(t *testing.T) *fiber.App {
	t.Helper()
	limiter = newBruteForceLimiter(time.Now)
	c := &Config{Basic: &BasicConfig{
		Username:                        "john.doe",
		PasswordBcryptHashBase64Encoded: hunter2BcryptB64,
		LoginForm:                       true,
	}}
	if !c.ValidateAndSetDefaults() {
		t.Fatal("expected config to be valid")
	}
	app := fiber.New()
	if err := c.RegisterHandlers(app); err != nil {
		t.Fatal("expected no error, got", err)
	}
	if err := c.ApplySecurityMiddleware(app); err != nil {
		t.Fatal("expected no error, got", err)
	}
	app.Get("/protected", func(ctx *fiber.Ctx) error { return ctx.SendStatus(200) })
	return app
}

func doRequest(t *testing.T, app *fiber.App, request *http.Request) *http.Response {
	t.Helper()
	response, err := app.Test(request)
	if err != nil {
		t.Fatal("expected no error, got", err)
	}
	return response
}

func postLogin(t *testing.T, app *fiber.App, username, password string) *http.Response {
	t.Helper()
	request := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	request.Header.Set("Content-Type", "application/json")
	return doRequest(t, app, request)
}

func sessionCookie(response *http.Response) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == cookieNameSession {
			return cookie
		}
	}
	return nil
}

func TestLogin_Success(t *testing.T) {
	app := newLoginFormApp(t)
	response := postLogin(t, app, "john.doe", "hunter2")
	if response.StatusCode != 200 {
		t.Fatal("expected 200, got", response.StatusCode)
	}
	cookie := sessionCookie(response)
	if cookie == nil || len(cookie.Value) == 0 || !cookie.HttpOnly {
		t.Fatalf("expected a non-empty HttpOnly session cookie, got %+v", cookie)
	}
	if cookie.Secure {
		t.Error("expected Secure=false for a plain-http request")
	}
	request := httptest.NewRequest("GET", "/protected", http.NoBody)
	request.AddCookie(&http.Cookie{Name: cookieNameSession, Value: cookie.Value})
	if code := doRequest(t, app, request).StatusCode; code != 200 {
		t.Error("expected 200 with session cookie, got", code)
	}
	if code := doRequest(t, app, httptest.NewRequest("GET", "/protected", http.NoBody)).StatusCode; code != 401 {
		t.Error("expected 401 without session cookie, got", code)
	}
}

func TestLogin_FormEncoded(t *testing.T) {
	app := newLoginFormApp(t)
	request := httptest.NewRequest("POST", "/login", strings.NewReader("username=john.doe&password=hunter2"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if code := doRequest(t, app, request).StatusCode; code != 200 {
		t.Error("expected 200, got", code)
	}
}

func TestLogin_WrongCredentials(t *testing.T) {
	app := newLoginFormApp(t)
	for _, credentials := range [][2]string{{"john.doe", "wrong"}, {"jane.doe", "hunter2"}} {
		response := postLogin(t, app, credentials[0], credentials[1])
		if response.StatusCode != 401 {
			t.Fatalf("expected 401 for %v, got %d", credentials, response.StatusCode)
		}
		body, _ := io.ReadAll(response.Body)
		if string(body) != `{"error":"invalid credentials"}` {
			t.Errorf("unexpected body %s", body)
		}
		if sessionCookie(response) != nil {
			t.Error("expected no session cookie on failure")
		}
	}
}

func TestLogin_BlocksAfterMaxAttempts(t *testing.T) {
	app := newLoginFormApp(t)
	for i := 0; i < 5; i++ {
		if code := postLogin(t, app, "john.doe", "wrong").StatusCode; code != 401 {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, code)
		}
	}
	response := postLogin(t, app, "john.doe", "hunter2")
	if response.StatusCode != 429 {
		t.Fatal("expected 429 for a blocked IP even with the right password, got", response.StatusCode)
	}
	if retryAfter := response.Header.Get("Retry-After"); retryAfter != "1800" {
		t.Error("expected Retry-After 1800, got", retryAfter)
	}
	body, _ := io.ReadAll(response.Body)
	if string(body) != `{"error":"too many failed attempts"}` {
		t.Errorf("unexpected body %s", body)
	}
}

func TestLogin_SuccessResetsFailures(t *testing.T) {
	app := newLoginFormApp(t)
	for i := 0; i < 4; i++ {
		postLogin(t, app, "john.doe", "wrong")
	}
	if code := postLogin(t, app, "john.doe", "hunter2").StatusCode; code != 200 {
		t.Fatal("expected 200, got", code)
	}
	for i := 0; i < 4; i++ {
		if code := postLogin(t, app, "john.doe", "wrong").StatusCode; code != 401 {
			t.Fatalf("expected 401 after reset, got %d", code)
		}
	}
}

func TestLogin_MalformedBodyNotCounted(t *testing.T) {
	app := newLoginFormApp(t)
	for i := 0; i < 10; i++ {
		request := httptest.NewRequest("POST", "/login", strings.NewReader("{"))
		request.Header.Set("Content-Type", "application/json")
		if code := doRequest(t, app, request).StatusCode; code != 400 {
			t.Fatalf("expected 400, got %d", code)
		}
	}
	if code := postLogin(t, app, "john.doe", "hunter2").StatusCode; code != 200 {
		t.Error("expected malformed requests not to count as failures, got", code)
	}
}

func TestLogout(t *testing.T) {
	app := newLoginFormApp(t)
	cookie := sessionCookie(postLogin(t, app, "john.doe", "hunter2"))
	if cookie == nil {
		t.Fatal("expected session cookie")
	}
	request := httptest.NewRequest("POST", "/logout", http.NoBody)
	request.AddCookie(&http.Cookie{Name: cookieNameSession, Value: cookie.Value})
	if code := doRequest(t, app, request).StatusCode; code != 200 {
		t.Fatal("expected 200, got", code)
	}
	request = httptest.NewRequest("GET", "/protected", http.NoBody)
	request.AddCookie(&http.Cookie{Name: cookieNameSession, Value: cookie.Value})
	if code := doRequest(t, app, request).StatusCode; code != 401 {
		t.Error("expected 401 after logout, got", code)
	}
}

func TestLogin_NotRegisteredWithoutLoginForm(t *testing.T) {
	c := &Config{Basic: &BasicConfig{Username: "john.doe", PasswordBcryptHashBase64Encoded: hunter2BcryptB64}}
	app := fiber.New()
	if err := c.RegisterHandlers(app); err != nil {
		t.Fatal(err)
	}
	if code := doRequest(t, app, httptest.NewRequest("POST", "/login", http.NoBody)).StatusCode; code != 404 {
		t.Error("expected 404, got", code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./security/ -run 'TestLogin|TestLogout' -v`
Expected: FAIL — `/login` returns 404 / 401 instead of 200.

- [ ] **Step 3: Implement**

- `security/login.go`:
  - `loginHandler` order: (1) `ip := c.clientIP(ctx)`; `limiter.Blocked(ip)` → 429 + `Retry-After` (ceil seconds) + error JSON; (2) `ctx.BodyParser` into `struct{ Username string \`json:"username" form:"username"\`; Password string \`json:"password" form:"password"\` }` → on error or empty username/password 400 `invalid request` (not counted); (3) `usernameOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(c.Basic.Username)) == 1`, then always `bcrypt.CompareHashAndPassword(hash, password)`; (4) failure → `if limiter.Fail(ip) { logr.Warnf("[security.loginHandler] Blocking IP %s for %s after too many failed login attempts", ip, c.BruteForce.BlockDuration) }`, 401 `invalid credentials`; (5) success → `limiter.Reset(ip)`, token = base64.RawURLEncoding of 32 bytes from `crypto/rand`, `sessions.SetWithTTL(token, c.Basic.Username, c.Basic.SessionTTL)`, cookie `gatus_session` (`Path=/`, `HTTPOnly`, `SameSite=Lax`, `Expires=now+SessionTTL`, `Secure = ctx.Protocol()=="https" || (isTrustedProxy(ctx.Context().RemoteIP(), c.trustedNets()) && ctx.Get("X-Forwarded-Proto")=="https")`), 200 `{}`.
  - `logoutHandler`: `sessions.Delete(ctx.Cookies(cookieNameSession))` when non-empty; expire cookie (`Expires` in the past, same attributes); 200 `{}`.
- `security/config.go`:
  - `RegisterHandlers`: after the OIDC block, `if c.Basic != nil && c.Basic.LoginForm { limiter.configure(c.BruteForce); router.Post("/login", c.loginHandler); router.Post("/logout", c.logoutHandler); logr.Info(...) }`.
  - `ApplySecurityMiddleware`: `if c.usesSessions()` → existing g8 session-gate code (unchanged); `else if c.Basic != nil` → existing Basic Auth code, using `decodedPasswordHash()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./security/ -v -race`
Expected: PASS — new tests plus existing `TestConfig_ApplySecurityMiddleware/basic` and `/oidc`.

- [ ] **Step 5: Commit**

```bash
git add security/login.go security/login_test.go security/config.go security/basic.go
git commit -m "feat(security): add form login and logout with per-IP blocking"
```

---

### Task 5: Expose `loginForm` in `/api/v1/config`, API wiring test

**Files:**
- Modify: `api/config.go:18-31`
- Modify: `api/config_test.go` (expected body)
- Test: `api/api_test.go` (new test)

**Interfaces:**
- Consumes: `security.BasicConfig.LoginForm`, routes from Task 4.
- Produces: `/api/v1/config` JSON key `loginForm` (bool), consumed by Task 6.

- [ ] **Step 1: Write the failing tests**

In `api/config_test.go` change the expected body (both the comparison and the error message) to:
`{"announcements":[],"authenticated":false,"loginForm":false,"oidc":true}`

Append to `api/api_test.go` (add imports `"io"`, `"strings"`):

```go
func TestNew_LoginForm(t *testing.T) {
	cfg := &config.Config{UI: &ui.Config{}, Security: &security.Config{
		Basic: &security.BasicConfig{
			Username:                        "john.doe",
			PasswordBcryptHashBase64Encoded: "JDJhJDA4JDFoRnpPY1hnaFl1OC9ISlFsa21VS09wOGlPU1ZOTDlHZG1qeTFvb3dIckRBUnlHUmNIRWlT",
			LoginForm:                       true,
		},
	}}
	if !cfg.Security.ValidateAndSetDefaults() {
		t.Fatal("expected security config to be valid")
	}
	router := New(cfg).Router()
	readBody := func(response *http.Response) string {
		body, _ := io.ReadAll(response.Body)
		return string(body)
	}
	// Unauthenticated: config says login form, statuses are protected
	response, _ := router.Test(httptest.NewRequest("GET", "/api/v1/config", http.NoBody))
	if body := readBody(response); !strings.Contains(body, `"authenticated":false`) || !strings.Contains(body, `"loginForm":true`) {
		t.Fatal("unexpected config body before login:", body)
	}
	response, _ = router.Test(httptest.NewRequest("GET", "/api/v1/endpoints/statuses", http.NoBody))
	if response.StatusCode != fiber.StatusUnauthorized {
		t.Fatal("expected 401 before login, got", response.StatusCode)
	}
	// Login
	request := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"john.doe","password":"hunter2"}`))
	request.Header.Set("Content-Type", "application/json")
	response, _ = router.Test(request)
	if response.StatusCode != fiber.StatusOK {
		t.Fatal("expected 200 from /login, got", response.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == "gatus_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected gatus_session cookie")
	}
	// Authenticated
	request = httptest.NewRequest("GET", "/api/v1/config", http.NoBody)
	request.AddCookie(sessionCookie)
	response, _ = router.Test(request)
	if body := readBody(response); !strings.Contains(body, `"authenticated":true`) {
		t.Error("expected authenticated=true after login, got", body)
	}
	request = httptest.NewRequest("GET", "/api/v1/endpoints/statuses", http.NoBody)
	request.AddCookie(sessionCookie)
	response, _ = router.Test(request)
	if response.StatusCode == fiber.StatusUnauthorized {
		t.Error("expected protected route to accept the session cookie")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/ -run 'TestConfigHandler_ServeHTTP|TestNew_LoginForm' -v`
Expected: FAIL — body lacks `loginForm`.

- [ ] **Step 3: Implement** — in `GetConfig`, compute `hasLoginForm := securityConfig.Basic != nil && securityConfig.Basic.LoginForm` (false when `securityConfig == nil`) and add `"loginForm": hasLoginForm` to the response map; include it in the existing debug log line.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./api/ ./security/ -v > /tmp/login-form-task5.log 2>&1; echo exit=$?` then `grep -E '^(--- FAIL|FAIL|ok)' /tmp/login-form-task5.log`
Expected: `exit=0`, both packages `ok`.

- [ ] **Step 5: Commit**

```bash
git add api/config.go api/config_test.go api/api_test.go
git commit -m "feat(api): expose loginForm in /api/v1/config"
```

---

### Task 6: Frontend login form and logout

**Files:**
- Modify: `web/app/src/App.vue`
- Regenerated: `web/static/**` (by `make frontend-build`)

**Interfaces:**
- Consumes: `/api/v1/config` `{oidc, loginForm, authenticated}` (Task 5); `POST /login` JSON `{username,password}` → 200 / 401 / 429 + `Retry-After`; `POST /logout` → 200.

No frontend test framework exists in this repo; behaviour is verified in the browser in Task 8.

- [ ] **Step 1: Gate condition** — line 9 becomes `v-else-if="!config || !(config.oidc || config.loginForm) || config.authenticated"`; default `config` ref becomes `{ oidc: false, loginForm: false, authenticated: true }`.

- [ ] **Step 2: Login screen** — rename the comment to `<!-- Login Screen -->`. Inside `CardContent`, after the existing `route.query.error` block:
  - When `config.loginForm`: a `<form @submit.prevent="submitLogin" class="space-y-4">` with `Input` (from `@/components/ui/input`) for username (`autocomplete="username"`, `required`, `autofocus`) and password (`type="password"`, `autocomplete="current-password"`, `required`), each with a `<label>`; an error box styled like the existing `route.query.error` box showing `loginError` when set; a full-width `Button type="submit"` with `:disabled="isLoginLoading"` showing `<Loading size="xs" />` while loading, else `LogIn` icon + `Sign in`.
  - When both `config.loginForm` and `config.oidc`: a divider row (`<div class="flex items-center gap-3 my-4"><div class="h-px flex-1 bg-border"></div><span class="text-xs text-muted-foreground">or</span><div class="h-px flex-1 bg-border"></div></div>`).
  - The existing OIDC `<a>` button gets `v-if="config.oidc"`.
  - Use only theme token classes (`bg-card`, `text-muted-foreground`, `border`, `bg-destructive/10` …) as the existing screen does, so dark mode follows the theme.

- [ ] **Step 3: Script** — new refs `loginUsername`, `loginPassword`, `loginError`, `isLoginLoading`; import `LogOut` from `lucide-vue-next` and `Input`.
  - `submitLogin()`: `POST /login`, `credentials: 'include'`, JSON body. 200 → clear password and error, `await fetchConfig()`. 401 → `Invalid username or password`. 429 → `Too many failed attempts. Try again in ${Math.ceil(Number(response.headers.get('Retry-After') || 60) / 60)} min.` Other status → `Login failed (HTTP ${response.status})`. Network error → `Login failed: server unreachable`. Always reset `isLoginLoading` in `finally`.
  - `logout()`: `POST /logout` with `credentials: 'include'`, then `await fetchConfig()`.

- [ ] **Step 4: Logout button** — in the header's right-hand nav area, `<Button v-if="config.loginForm && config.authenticated" variant="ghost" size="sm" @click="logout"><LogOut class="mr-2 h-4 w-4" />Logout</Button>`, visible on mobile and desktop.

- [ ] **Step 5: Build**

Run: `make frontend-build > /tmp/login-form-frontend.log 2>&1; echo exit=$?`
Expected: `exit=0`. Then `go test ./api/ -run TestNew -v` → PASS (static assets still served).

- [ ] **Step 6: Commit** — run `git status` and add every changed file (App.vue and all of `web/static/`):

```bash
git add web/app/src/App.vue web/static
git commit -m "feat(ui): add username/password login form and logout button"
```

---

### Task 7: mise tasks, multi-arch Dockerfile, README

**Files:**
- Create: `mise.toml`
- Modify: `Dockerfile`
- Modify: `README.md` (section `#### Basic Authentication`, around line 2825)

- [ ] **Step 1: Dockerfile cross-compilation** — builder stage becomes `FROM --platform=$BUILDPLATFORM golang:alpine AS builder`, add `ARG TARGETOS TARGETARCH`, and the build line becomes:

```dockerfile
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -installsuffix cgo -o gatus .
```

Everything else in the Dockerfile is unchanged.

- [ ] **Step 2: Write `mise.toml`** (exact content)

```toml
min_version = "2026.9.0"

[settings]
experimental = true              # [deps] is experimental

[deps.web]
auto = true
sources = ["web/app/package.json", "web/app/package-lock.json"]
outputs = ["web/app/node_modules/.package-lock.json"]
run = "npm --prefix web/app ci"

[tasks.dev]
description = "Run Gatus locally against ./config.yaml"
env = { ENVIRONMENT = "dev", GATUS_CONFIG_PATH = "./config.yaml" }
run = "go run ."

[tasks.build]
description = "Build the gatus binary into ./gatus"
run = "go build -o gatus ."

[tasks."build:web"]
description = "Rebuild the embedded UI (web/static) after web/app changes"
run = "npm --prefix web/app run build"

[tasks.test]
description = "Run Go unit tests"
run = "go test ./... -cover"

[tasks.ci]
description = "Gate: vet and unit tests"
depends = ["test"]
run = "go vet ./..."

# Local single-arch image, loaded into the docker daemon.
[tasks."docker:build"]
description = "Build the image locally as $IMAGE:<sha> and :latest"
run = """
set -eu
image="${IMAGE:-cuongtransc/gatus}"
tag="$(git rev-parse --short HEAD)"
docker buildx build --load -t "$image:$tag" -t "$image:latest" .
"""

# Multi-arch build needs a docker-container builder; created once, reused after.
# Requires `docker login` to the registry first.
[tasks.release]
description = "Build amd64+arm64 image and push $IMAGE:<sha> and :latest"
run = """
set -eu
image="${IMAGE:-cuongtransc/gatus}"
tag="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain)" ]; then
  echo "release: working tree is dirty; commit first so the tag matches the image" >&2
  exit 1
fi
docker buildx inspect gatus-multiarch >/dev/null 2>&1 \
  || docker buildx create --name gatus-multiarch --driver docker-container >/dev/null
docker buildx build --builder gatus-multiarch \
  --platform linux/amd64,linux/arm64 \
  -t "$image:$tag" -t "$image:latest" --push .
echo "pushed $image:$tag and $image:latest"
"""
```

- [ ] **Step 3: Verify tasks**

Run: `mise tasks` → lists `build build:web ci dev docker:build release test`.
Run: `ct mise lint mise.toml; echo exit=$?` → `exit=0`.
Run: `mise run ci > /tmp/login-form-ci.log 2>&1; echo exit=$?` → `exit=0`.
Guard check: with a scratch untracked file present, `mise run release; echo exit=$?` → prints the dirty-tree message, `exit=1`; delete the scratch file.

- [ ] **Step 4: README** — in `#### Basic Authentication`, add to the table:

```
| `security.basic.login-form`  | Show a username/password form in the UI instead of the browser's Basic Auth prompt. Uses a session cookie. | `false` |
| `security.basic.session-ttl` | Session lifetime when `login-form` is enabled.                                                             | `8h`    |
```

Then add a `#### Brute-force protection` subsection after it: one sentence (failed form logins are counted per client IP; the IP comes from `CF-Connecting-IP` only when the connection comes from a Cloudflare IP range or a `trusted-proxies` entry; state is in memory, per instance) and the table:

```
| Parameter                             | Description                                                      | Default |
|:--------------------------------------|:-----------------------------------------------------------------|:--------|
| `security.brute-force.max-attempts`   | Failed logins from one IP within `window` before it is blocked.  | `5`     |
| `security.brute-force.window`         | Period in which failed logins are counted.                       | `15m`   |
| `security.brute-force.block-duration` | How long a blocked IP gets `429` on `/login`.                    | `30m`   |
| `security.brute-force.trusted-proxies`| Extra IPs/CIDRs (e.g. a cloudflared tunnel) allowed to set `CF-Connecting-IP`. | `[]` |
```

- [ ] **Step 5: Commit**

```bash
git add mise.toml Dockerfile README.md
git commit -m "build: add mise tasks and multi-arch image release to cuongtransc/gatus"
```

---

### Task 8: Real-run verification

No code unless a defect is found (then: failing test first, fix, re-run this task).

- [ ] **Step 1: Full gate** — `mise run ci > /tmp/login-form-ci.log 2>&1; echo exit=$?` → `exit=0`.

- [ ] **Step 2: Run the binary** with a scratch config in the session scratchpad: `security.basic` (`john.doe` / hash of `hunter2` above), `login-form: true`, `brute-force.max-attempts: 3`, one endpoint. `GATUS_CONFIG_PATH=<scratch>/config.yaml ./gatus` in the background, log to `/tmp/login-form-run.log`.

- [ ] **Step 3: Browser check** (claude-in-chrome) at `http://localhost:8080`: login form renders (no Basic popup); wrong password shows `Invalid username or password`; right password shows the dashboard; Logout returns to the form; reload after logout stays on the form. Repeat the render check in dark mode. Screenshot each state.

- [ ] **Step 4: Block check** — 3 wrong logins in the browser → message `Too many failed attempts. Try again in 30 min.`; server log contains `Blocking IP`. With curl from a non-Cloudflare peer, `-H 'CF-Connecting-IP: 1.2.3.4'` after the block still returns 429 (header ignored).

- [ ] **Step 5: Docker** — `mise run docker:build > /tmp/login-form-docker.log 2>&1; echo exit=$?` → `exit=0`; `docker run --rm -p 18080:8080 cuongtransc/gatus:latest` answers `/health` with 200. Do **not** run `mise run release` unless the user asks.

- [ ] **Step 6: Stop the background process**; report results with screenshots paths.
