# Login form + brute-force IP blocking — design

Date: 2026-10-22 · Branch: `feat/login-form`

## Goal

Replace the browser Basic Auth popup with a username/password form in the Gatus UI, block
client IPs that fail login too often, and resolve the client IP correctly behind Cloudflare.
Add a `mise.toml` that builds and pushes the Docker image to `cuongtransc/gatus`.

## Decisions (from the brainstorm)

- **Opt-in, Basic kept.** `security.basic.login-form: true` switches to form login. Without it,
  Basic Auth behaves exactly as today (no breaking change, keeps upstream merges easy).
- **Cloudflare IP trusted only from Cloudflare peers.** `CF-Connecting-IP` is honoured only when
  the TCP peer is inside Cloudflare's published ranges or a configured `trusted-proxies` CIDR.
- **Docker image is multi-arch** (`linux/amd64,linux/arm64`).

## Configuration

```yaml
security:
  basic:
    username: admin
    password-bcrypt-base64: "..."
    login-form: true        # new, default false
    session-ttl: 8h         # new, default 8h (same default as OIDC); only used with login-form
  brute-force:              # new, optional; defaults apply when login-form is on
    max-attempts: 5         # failed logins per IP within window before blocking
    window: 15m
    block-duration: 30m
    trusted-proxies: []     # extra CIDRs allowed to set CF-Connecting-IP (e.g. cloudflared tunnel)
```

Validation (fatal at startup, as for other config): `max-attempts >= 1`, `window > 0`,
`block-duration > 0`, every `trusted-proxies` entry parses as a CIDR or a bare IP.
`login-form` may be combined with `oidc`: both create sessions in the same store, so one
session middleware accepts either; the UI then shows the form and the OIDC button.

## Backend

### Routes (registered in `RegisterHandlers`, i.e. unprotected)

- `POST /login` — body JSON `{"username","password"}` or form-encoded.
  1. `ip := ClientIP(ctx)`; if `limiter.Blocked(ip)` → `429` + `Retry-After: <seconds>`.
  2. bcrypt compare always runs (also for a wrong username, against the configured hash) so
     response time does not reveal valid usernames.
  3. Failure → `limiter.Fail(ip)`, `401 {"error":"invalid credentials"}`. If this failure trips
     the block, log `WARN` with IP and duration.
  4. Success → `limiter.Reset(ip)`, 32-byte random token (`crypto/rand`, base64url) stored in the
     existing `sessions` cache with `session-ttl`, cookie `gatus_session` (`HttpOnly`,
     `SameSite=Lax`, `Path=/`, `Secure` when the request scheme is https or
     `X-Forwarded-Proto`/CF says https from a trusted peer), `200`.
- `POST /logout` — deletes the session from `sessions`, expires the cookie, `200`.

### Middleware

`ApplySecurityMiddleware` gains a session branch for `Basic != nil && Basic.LoginForm`, reusing
the g8 + `gatus_session` cookie path that OIDC uses today (extracted into one helper so both
call it). `IsAuthenticated` already works off `c.gate`, so it covers form sessions unchanged.

### Client IP — `security/clientip.go`

`ClientIP(ctx *fiber.Ctx) string`:
- `peer := ctx.Context().RemoteIP()`.
- If `peer` ∈ Cloudflare ranges (embedded IPv4 + IPv6 list) or `trusted-proxies`, and
  `CF-Connecting-IP` parses as an IP → return it (normalised via `net.ParseIP().String()`).
- Otherwise return `peer`. `X-Forwarded-For` is never read.

The Cloudflare list is a Go slice in the package with a comment pointing to
`https://www.cloudflare.com/ips/`; no runtime fetch.

### Limiter — `security/bruteforce.go`

Package-level (like `sessions`) so state survives config hot-reload; config values are
re-applied on reload.

- `Fail(ip)`: record failure; failures older than `window` are dropped; reaching
  `max-attempts` sets `blockedUntil = now + block-duration` and clears the counter.
- `Blocked(ip) (bool, time.Duration)`, `Reset(ip)`.
- Bounded memory: at most 10 000 tracked IPs; expired entries are pruned on access and by a
  periodic sweep; when full, the oldest non-blocked entry is evicted.
- Injectable clock for tests.

Known limits: state is in-memory, so it is per replica and lost on restart. Acceptable for a
single-instance Gatus.

### `/api/v1/config`

Adds `"loginForm": <bool>` next to `"oidc"`. `authenticated` keeps its meaning.

## Frontend (`web/app/src/App.vue`)

The existing login screen (today OIDC-only) renders when `(config.oidc || config.loginForm) &&
!config.authenticated`. With `loginForm`: username + password inputs and a submit button,
`fetch('/login', {method:'POST', credentials:'include'})`, then reload config/statuses on 200,
show "Invalid username or password" on 401 and "Too many attempts, try again in N min" on 429.
A logout button appears in the header when `loginForm && authenticated`. Tailwind with `dark:`
variants; props-based, no provide/inject. `web/static/` is regenerated with `make frontend-build`.

## mise (`mise.toml`)

Tasks: `build` (go build), `test` (go test ./...), `frontend:build`, `docker:build`
(`docker buildx build --platform linux/amd64,linux/arm64 -t cuongtransc/gatus:<git short sha>
-t cuongtransc/gatus:latest`), `docker:push` (same build with `--push`), `ci` (frontend build +
test). Image name overridable via `IMAGE` env var.

## Testing

- `clientip_test.go`: CF peer + valid header, CF peer + garbage header, non-CF peer with header
  (ignored), trusted-proxy CIDR, IPv6 peer and header.
- `bruteforce_test.go`: below threshold not blocked, threshold blocks, block expires, window
  expiry forgets old failures, `Reset`, capacity eviction.
- `basic_test.go` / config tests: validation of new fields and defaults.
- API tests (`api/`): form login success sets cookie and protected route returns 200; wrong
  password 401; 5 failures → 429 with `Retry-After`; Basic mode unchanged (existing tests).
- Real run before calling done: start the binary with a `login-form` config, log in through the
  browser in both light and dark themes, trigger the block, check `docker:build` produces an
  image (push only when the user asks).
