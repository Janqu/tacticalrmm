package httpapi

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicAndUnauthenticatedRequests(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	for _, test := range []struct {
		path string
		code int
		body string
	}{
		{"/", 200, `{"status":"ok"}`},
		{"/core/version/", 401, `{"detail":"Authentication credentials were not provided."}`},
		{"/accounts/roles/", 401, `{"detail":"Authentication credentials were not provided."}`},
		{"/unknown/", 404, `{"detail":"Not found."}`},
		{"/accounts/+1/users/", 404, `{"detail":"Not found."}`},
		{"/accounts/-1/users/", 404, `{"detail":"Not found."}`},
	} {
		t.Run(test.path, func(t *testing.T) {
			response, err := app.Test(httptest.NewRequest("GET", test.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.code || strings.TrimSpace(string(body)) != test.body {
				t.Fatalf("got %d %s; want %d %s", response.StatusCode, body, test.code, test.body)
			}
			if test.code == 401 && response.Header.Get("WWW-Authenticate") != "Token" {
				t.Fatal("missing auth challenge")
			}
		})
	}
}

func TestDjangoDatetime(t *testing.T) {
	value := time.Date(2024, 1, 2, 3, 4, 5, 123400000, time.UTC)
	if got := *datetime(&value); got != "2024-01-02T03:04:05.123400Z" {
		t.Fatal(got)
	}
	value = value.Truncate(time.Second)
	if got := *datetime(&value); got != "2024-01-02T03:04:05Z" {
		t.Fatal(got)
	}
	if datetime(nil) != nil {
		t.Fatal("null datetime changed")
	}
}

func TestLoginRequiresSigningKeyAndRateLimiter(t *testing.T) {
	for _, config := range []LoginConfig{{}, {SecretKey: "test-only"}} {
		app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{Login: config})
		for _, path := range []string{"/v2/checkcreds/", "/v2/login/"} {
			response, err := app.Test(httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 503 {
				t.Fatalf("unconfigured login returned %d", response.StatusCode)
			}
		}
	}
}

func TestHeadAccountRoutesRequireAuthentication(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	for _, path := range []string{"/accounts/1/users/", "/accounts/users/1/sessions/", "/accounts/roles/", "/accounts/roles/1/"} {
		response, err := app.Test(httptest.NewRequest("HEAD", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Errorf("HEAD %s returned %d", path, response.StatusCode)
		}
	}
}
