package security

import (
	"net/http"

	g8 "github.com/TwiN/g8/v2"
	"github.com/TwiN/logr"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"golang.org/x/crypto/bcrypt"
)

const (
	cookieNameState   = "gatus_state"
	cookieNameNonce   = "gatus_nonce"
	cookieNameSession = "gatus_session"
)

// Config is the security configuration for Gatus
type Config struct {
	Basic *BasicConfig `yaml:"basic,omitempty"`
	OIDC  *OIDCConfig  `yaml:"oidc,omitempty"`

	// BruteForce configures IP blocking for the login form. Defaults are applied when Basic.LoginForm is enabled.
	BruteForce *BruteForceConfig `yaml:"brute-force,omitempty"`

	gate *g8.Gate

	// passwordHash is the decoded bcrypt hash, set by RegisterHandlers when the login form is enabled
	passwordHash []byte
}

// ValidateAndSetDefaults returns whether the security configuration is valid or not and sets default values.
func (c *Config) ValidateAndSetDefaults() bool {
	if (c.Basic != nil && !c.Basic.isValid()) || (c.OIDC != nil && !c.OIDC.ValidateAndSetDefaults()) {
		return false
	}
	if c.Basic != nil && c.Basic.LoginForm {
		if c.Basic.SessionTTL < 0 {
			return false
		}
		if c.Basic.SessionTTL == 0 {
			c.Basic.SessionTTL = DefaultBasicSessionTTL
		}
		if c.BruteForce == nil {
			c.BruteForce = &BruteForceConfig{}
		}
	}
	if c.BruteForce != nil {
		return c.BruteForce.ValidateAndSetDefaults()
	}
	return true
}

// RegisterHandlers registers all handlers required based on the security configuration
func (c *Config) RegisterHandlers(router fiber.Router) error {
	if c.OIDC != nil {
		if err := c.OIDC.initialize(); err != nil {
			logr.Errorf("[security.RegisterHandlers] Failed to initialize OIDC provider: %s", err.Error())
			return err
		}
		router.All("/oidc/login", c.OIDC.loginHandler)
		router.All("/authorization-code/callback", adaptor.HTTPHandlerFunc(c.OIDC.callbackHandler))
		logr.Infof("[security.RegisterHandlers] Registered OIDC routes (/oidc/login, /authorization-code/callback)")
	}
	if c.Basic != nil && c.Basic.LoginForm {
		hash, err := c.Basic.decodedPasswordHash()
		if err != nil {
			logr.Errorf("[security.RegisterHandlers] Failed to decode password-bcrypt-base64: %s", err.Error())
			return err
		}
		c.passwordHash = hash
		limiter.configure(c.BruteForce)
		router.Post("/login", c.loginHandler)
		router.Post("/logout", c.logoutHandler)
		logr.Infof("[security.RegisterHandlers] Registered login form routes (/login, /logout)")
	}
	return nil
}

// ApplySecurityMiddleware applies an authentication middleware to the router passed.
// The router passed should be a sub-router in charge of handlers that require authentication.
func (c *Config) ApplySecurityMiddleware(router fiber.Router) error {
	if c.usesSessions() {
		// We're going to use g8 for session handling
		clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
			if _, exists := sessions.Get(token); exists {
				return g8.NewClient(token)
			}
			return nil
		})
		customTokenExtractorFunc := func(request *http.Request) string {
			sessionCookie, err := request.Cookie(cookieNameSession)
			if err != nil {
				return ""
			}
			return sessionCookie.Value
		}
		// TODO: g8: Add a way to update cookie after? would need the writer
		authorizationService := g8.NewAuthorizationService().WithClientProvider(clientProvider)
		c.gate = g8.New().WithAuthorizationService(authorizationService).WithCustomTokenExtractor(customTokenExtractorFunc)
		router.Use(adaptor.HTTPMiddleware(c.gate.Protect))
	} else if c.Basic != nil {
		decodedBcryptHash, err := c.Basic.decodedPasswordHash()
		if err != nil {
			return err
		}
		router.Use(basicauth.New(basicauth.Config{
			Authorizer: func(username, password string) bool {
				if len(c.Basic.PasswordBcryptHashBase64Encoded) > 0 {
					if username != c.Basic.Username || bcrypt.CompareHashAndPassword(decodedBcryptHash, []byte(password)) != nil {
						return false
					}
				}
				return true
			},
			Unauthorized: func(ctx *fiber.Ctx) error {
				ctx.Set("WWW-Authenticate", "Basic")
				return ctx.Status(401).SendString("Unauthorized")
			},
		}))
	}
	return nil
}

// IsAuthenticated checks whether the user is authenticated
// If the Config does not warrant authentication, it will always return true.
func (c *Config) IsAuthenticated(ctx *fiber.Ctx) bool {
	if c.gate != nil {
		// TODO: Update g8 to support fasthttp natively? (see g8's fasthttp branch)
		request, err := adaptor.ConvertRequest(ctx, false)
		if err != nil {
			logr.Errorf("[security.IsAuthenticated] Unexpected error converting request: %v", err)
			return false
		}
		token := c.gate.ExtractTokenFromRequest(request)
		if len(token) == 0 {
			logr.Debug("[security.IsAuthenticated] No session token found in request")
			return false
		}
		_, hasSession := sessions.Get(token)
		if hasSession {
			logr.Debug("[security.IsAuthenticated] Active session found")
		} else {
			logr.Debug("[security.IsAuthenticated] Session token expired or invalid")
		}
		return hasSession
	}
	return false
}
