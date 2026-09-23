package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestAllauthConfigWithoutAuthentication(t *testing.T) {
	app := fiber.New()
	s := &Server{}
	app.Get("/_allauth/browser/v1/config/", s.allauthConfig)
	response, err := app.Test(httptest.NewRequest("GET", "/_allauth/browser/v1/config/", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("unexpected status/cache headers: %d %v", response.StatusCode, response.Header)
	}
	var got map[string]any
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"status": float64(200),
		"data": map[string]any{
			"account": map[string]any{
				"authentication_method": "username", "is_open_for_signup": false,
				"email_verification_by_code_enabled": false, "login_by_code_enabled": false,
			},
			"socialaccount": map[string]any{"providers": []any{}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("login capability contract = %#v; want %#v", got, want)
	}
}
