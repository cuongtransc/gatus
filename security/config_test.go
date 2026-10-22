package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

func TestConfig_ValidateAndSetDefaults(t *testing.T) {
	validBasicConfig := &BasicConfig{
		Username:                        "test",
		PasswordBcryptHashBase64Encoded: "somevalue",
	}
	validOIDCConfig := &OIDCConfig{
		IssuerURL:    "testurl",
		RedirectURL:  "testredirecturl/authorization-code/callback",
		ClientID:     "testid",
		ClientSecret: "testsecret",
		Scopes:       []string{"testscope"},
	}

	type Scenario struct {
		Name        string
		Config      *Config
		ExpectValid bool
	}
	scenarios := []Scenario{
		{
			Name: "empty",
			Config: &Config{
				Basic: nil,
				OIDC:  nil,
			},
			ExpectValid: true,
		},
		{
			Name: "empty-basic",
			Config: &Config{
				Basic: &BasicConfig{},
				OIDC:  nil,
			},
			ExpectValid: false,
		},
		{
			Name: "empty-oidc",
			Config: &Config{
				Basic: nil,
				OIDC:  &OIDCConfig{},
			},
			ExpectValid: false,
		},
		{
			Name: "valid-basic-only",
			Config: &Config{
				Basic: validBasicConfig,
				OIDC:  nil,
			},
			ExpectValid: true,
		},
		{
			Name: "valid-oidc-only",
			Config: &Config{
				Basic: nil,
				OIDC:  validOIDCConfig,
			},
			ExpectValid: true,
		},
		{
			Name: "valid-basic-and-oidc",
			Config: &Config{
				Basic: validBasicConfig,
				OIDC:  validOIDCConfig,
			},
			ExpectValid: true,
		},
		{
			Name: "invalid-brute-force",
			Config: &Config{
				Basic:      validBasicConfig,
				BruteForce: &BruteForceConfig{MaxAttempts: -1},
			},
			ExpectValid: false,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			isValid := scenario.Config.ValidateAndSetDefaults()
			if isValid && !scenario.ExpectValid {
				t.Errorf("scenario %s: expected config to be invalid", scenario.Name)
			} else if !isValid && scenario.ExpectValid {
				t.Errorf("scenario %s: expected config to be valid", scenario.Name)
			}
		})
	}
}

func TestConfig_ApplySecurityMiddleware(t *testing.T) {
	///////////
	// BASIC //
	///////////
	t.Run("basic", func(t *testing.T) {
		// Bcrypt
		c := &Config{Basic: &BasicConfig{
			Username:                        "john.doe",
			PasswordBcryptHashBase64Encoded: "JDJhJDA4JDFoRnpPY1hnaFl1OC9ISlFsa21VS09wOGlPU1ZOTDlHZG1qeTFvb3dIckRBUnlHUmNIRWlT",
		}}
		app := fiber.New()
		if err := c.ApplySecurityMiddleware(app); err != nil {
			t.Error("expected no error, got", err)
		}
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.SendStatus(200)
		})
		// Try to access the route without basic auth
		request := httptest.NewRequest("GET", "/test", http.NoBody)
		response, err := app.Test(request)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if response.StatusCode != 401 {
			t.Error("expected code to be 401, but was", response.StatusCode)
		}
		// Try again, but with basic auth
		request = httptest.NewRequest("GET", "/test", http.NoBody)
		request.SetBasicAuth("john.doe", "hunter2")
		response, err = app.Test(request)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if response.StatusCode != 200 {
			t.Error("expected code to be 200, but was", response.StatusCode)
		}
	})
	//////////
	// OIDC //
	//////////
	t.Run("oidc", func(t *testing.T) {
		c := &Config{OIDC: &OIDCConfig{
			IssuerURL:       "https://sso.gatus.io/",
			RedirectURL:     "http://localhost:80/authorization-code/callback",
			Scopes:          []string{"openid"},
			AllowedSubjects: []string{"user1@example.com"},
			SessionTTL:      DefaultOIDCSessionTTL,
			oauth2Config:    oauth2.Config{},
			verifier:        nil,
		}}
		app := fiber.New()
		if err := c.ApplySecurityMiddleware(app); err != nil {
			t.Error("expected no error, got", err)
		}
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.SendStatus(200)
		})
		// Try without any session cookie
		request := httptest.NewRequest("GET", "/test", http.NoBody)
		response, err := app.Test(request)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if response.StatusCode != 401 {
			t.Error("expected code to be 401, but was", response.StatusCode)
		}
		// Try with a session cookie
		request = httptest.NewRequest("GET", "/test", http.NoBody)
		request.AddCookie(&http.Cookie{Name: "session", Value: "123"})
		response, err = app.Test(request)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if response.StatusCode != 401 {
			t.Error("expected code to be 401, but was", response.StatusCode)
		}
	})
}

func TestConfig_RegisterHandlers(t *testing.T) {
	c := &Config{}
	app := fiber.New()
	c.RegisterHandlers(app)
	// Try to access the OIDC handler. This should fail, because the security config doesn't have OIDC
	request := httptest.NewRequest("GET", "/oidc/login", http.NoBody)
	response, err := app.Test(request)
	if err != nil {
		t.Fatal("expected no error, got", err)
	}
	if response.StatusCode != 404 {
		t.Error("expected code to be 404, but was", response.StatusCode)
	}
	// Set an empty OIDC config. This should fail, because the IssuerURL is required.
	c.OIDC = &OIDCConfig{}
	if err := c.RegisterHandlers(app); err == nil {
		t.Fatal("expected an error, but got none")
	}
	// Set the OIDC config and try again
	c.OIDC = &OIDCConfig{
		IssuerURL:       "https://sso.gatus.io/",
		RedirectURL:     "http://localhost:80/authorization-code/callback",
		Scopes:          []string{"openid"},
		AllowedSubjects: []string{"user1@example.com"},
	}
	if err := c.RegisterHandlers(app); err != nil {
		t.Fatal("expected no error, but got", err)
	}
	request = httptest.NewRequest("GET", "/oidc/login", http.NoBody)
	response, err = app.Test(request)
	if err != nil {
		t.Fatal("expected no error, got", err)
	}
	if response.StatusCode != 302 {
		t.Error("expected code to be 302, but was", response.StatusCode)
	}
}

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

func TestConfig_ValidateAndSetDefaults_LoginFormNegativeSessionTTL(t *testing.T) {
	c := &Config{Basic: &BasicConfig{
		Username:                        "test",
		PasswordBcryptHashBase64Encoded: "somevalue",
		LoginForm:                       true,
		SessionTTL:                      -time.Second,
	}}
	if c.ValidateAndSetDefaults() {
		t.Error("expected negative session-ttl to be invalid")
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
