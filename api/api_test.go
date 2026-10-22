package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TwiN/gatus/v5/config"
	"github.com/TwiN/gatus/v5/config/ui"
	"github.com/TwiN/gatus/v5/security"
	"github.com/gofiber/fiber/v2"
)

func TestNew(t *testing.T) {
	type Scenario struct {
		Name         string
		Path         string
		ExpectedCode int
		Gzip         bool
		WithSecurity bool
	}
	scenarios := []Scenario{
		{
			Name:         "health",
			Path:         "/health",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "custom.css",
			Path:         "/css/custom.css",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "custom.css-gzipped",
			Path:         "/css/custom.css",
			ExpectedCode: fiber.StatusOK,
			Gzip:         true,
		},
		{
			Name:         "metrics",
			Path:         "/metrics",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "favicon.ico",
			Path:         "/favicon.ico",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "app.js",
			Path:         "/js/app.js",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "app.js-gzipped",
			Path:         "/js/app.js",
			ExpectedCode: fiber.StatusOK,
			Gzip:         true,
		},
		{
			Name:         "chunk-vendors.js",
			Path:         "/js/chunk-vendors.js",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "chunk-vendors.js-gzipped",
			Path:         "/js/chunk-vendors.js",
			ExpectedCode: fiber.StatusOK,
			Gzip:         true,
		},
		{
			Name:         "index",
			Path:         "/",
			ExpectedCode: fiber.StatusOK,
		},
		{
			Name:         "index-html-redirect",
			Path:         "/index.html",
			ExpectedCode: fiber.StatusMovedPermanently,
		},
		{
			Name:         "index-should-return-200-even-if-not-authenticated",
			Path:         "/",
			ExpectedCode: fiber.StatusOK,
			WithSecurity: true,
		},
		{
			Name:         "endpoints-should-return-401-if-not-authenticated",
			Path:         "/api/v1/endpoints/statuses",
			ExpectedCode: fiber.StatusUnauthorized,
			WithSecurity: true,
		},
		{
			Name:         "config-should-return-200-even-if-not-authenticated",
			Path:         "/api/v1/config",
			ExpectedCode: fiber.StatusOK,
			WithSecurity: true,
		},
		{
			Name:         "config-should-always-return-200",
			Path:         "/api/v1/config",
			ExpectedCode: fiber.StatusOK,
			WithSecurity: false,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			cfg := &config.Config{Metrics: true, UI: &ui.Config{}}
			if scenario.WithSecurity {
				cfg.Security = &security.Config{
					Basic: &security.BasicConfig{
						Username:                        "john.doe",
						PasswordBcryptHashBase64Encoded: "JDJhJDA4JDFoRnpPY1hnaFl1OC9ISlFsa21VS09wOGlPU1ZOTDlHZG1qeTFvb3dIckRBUnlHUmNIRWlT",
					},
				}
			}
			api := New(cfg)
			router := api.Router()
			request := httptest.NewRequest("GET", scenario.Path, http.NoBody)
			if scenario.Gzip {
				request.Header.Set("Accept-Encoding", "gzip")
			}
			response, err := router.Test(request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != scenario.ExpectedCode {
				t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, scenario.ExpectedCode, response.StatusCode)
			}
		})
	}
}

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
