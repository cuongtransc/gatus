package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/TwiN/logr"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// isJSONRequest returns whether the request's Content-Type is application/json (parameters such as charset allowed).
// Only JSON is accepted on /login because a form-encoded POST can be sent cross-site without a CORS preflight.
func isJSONRequest(ctx *fiber.Ctx) bool {
	mediaType, _, _ := strings.Cut(ctx.Get(fiber.HeaderContentType), ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), fiber.MIMEApplicationJSON)
}

func jsonError(ctx *fiber.Ctx, status int, message string) error {
	ctx.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return ctx.Status(status).SendString(`{"error":"` + message + `"}`)
}

// usesSessions returns whether authentication is backed by the session store (OIDC or login form)
func (c *Config) usesSessions() bool {
	return c.OIDC != nil || (c.Basic != nil && c.Basic.LoginForm)
}

// loginHandler authenticates a username/password pair and creates a session
func (c *Config) loginHandler(ctx *fiber.Ctx) error {
	if !isJSONRequest(ctx) {
		return jsonError(ctx, fiber.StatusBadRequest, "invalid request")
	}
	var body loginRequest
	if err := ctx.BodyParser(&body); err != nil || body.Username == "" || body.Password == "" {
		return jsonError(ctx, fiber.StatusBadRequest, "invalid request")
	}
	ip := c.clientIP(ctx)
	allowed, retryAfter, blockedNow := limiter.Attempt(ip)
	if blockedNow {
		logr.Warnf("[security.loginHandler] Blocking IP %s for %s after too many failed login attempts", ip, c.BruteForce.BlockDuration)
	}
	if !allowed {
		ctx.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
		return jsonError(ctx, fiber.StatusTooManyRequests, "too many failed attempts")
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(c.Basic.Username)) == 1
	passwordErr := bcrypt.CompareHashAndPassword(c.passwordHash, []byte(body.Password))
	if !usernameOK || passwordErr != nil {
		return jsonError(ctx, fiber.StatusUnauthorized, "invalid credentials")
	}
	limiter.Reset(ip)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		logr.Errorf("[security.loginHandler] Failed to generate session token: %s", err.Error())
		return jsonError(ctx, fiber.StatusInternalServerError, "internal error")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sessions.SetWithTTL(token, c.Basic.Username, c.Basic.SessionTTL)
	ctx.Cookie(c.sessionCookie(ctx, token, time.Now().Add(c.Basic.SessionTTL)))
	ctx.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return ctx.Status(fiber.StatusOK).SendString("{}")
}

// logoutHandler deletes the session and expires the cookie
func (c *Config) logoutHandler(ctx *fiber.Ctx) error {
	if token := ctx.Cookies(cookieNameSession); token != "" {
		sessions.Delete(token)
	}
	ctx.Cookie(c.sessionCookie(ctx, "", time.Unix(0, 0)))
	ctx.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return ctx.Status(fiber.StatusOK).SendString("{}")
}

func (c *Config) sessionCookie(ctx *fiber.Ctx, value string, expires time.Time) *fiber.Cookie {
	secure := ctx.Protocol() == "https" ||
		(isTrustedProxy(ctx.Context().RemoteIP(), c.trustedNets()) && ctx.Get("X-Forwarded-Proto") == "https")
	return &fiber.Cookie{
		Name:     cookieNameSession,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   secure,
	}
}
