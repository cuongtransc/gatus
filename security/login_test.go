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
	for i := 0; i < 10; i++ {
		request := httptest.NewRequest("POST", "/login", strings.NewReader("username=john.doe&password=wrong"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := doRequest(t, app, request)
		if response.StatusCode != 400 {
			t.Fatalf("attempt %d: expected 400 for a form-encoded body, got %d", i+1, response.StatusCode)
		}
		body, _ := io.ReadAll(response.Body)
		if string(body) != `{"error":"invalid request"}` {
			t.Fatalf("unexpected body %s", body)
		}
	}
	if code := postLogin(t, app, "john.doe", "hunter2").StatusCode; code != 200 {
		t.Error("expected form-encoded requests not to count as attempts, got", code)
	}
}

func TestLogin_JSONWithCharset(t *testing.T) {
	app := newLoginFormApp(t)
	request := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"john.doe","password":"hunter2"}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
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

func TestLogin_RegisterHandlersRejectsMalformedHash(t *testing.T) {
	c := &Config{Basic: &BasicConfig{Username: "john.doe", PasswordBcryptHashBase64Encoded: "not-base64!!", LoginForm: true}}
	if !c.ValidateAndSetDefaults() {
		t.Fatal("expected config to be valid")
	}
	if err := c.RegisterHandlers(fiber.New()); err == nil {
		t.Error("expected an error for a malformed password hash")
	}
}
