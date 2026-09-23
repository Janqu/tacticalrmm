package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
)

func TestAlertChannelOptionsPermission(t *testing.T) {
	for _, tc := range []struct {
		role   accounts.Role
		status int
	}{
		{accounts.Role{}, 403},
		{accounts.Role{CanListAlerts: true}, 403},
		{accounts.Role{CanListSites: true}, 403},
		{accounts.Role{CanListAlerttemplates: true}, 204},
		{accounts.Role{CanManageAlerttemplates: true}, 204},
		{accounts.Role{CanManageSites: true}, 204},
		{accounts.Role{CanViewCoreSettings: true}, 204},
		{accounts.Role{CanEditAgent: true}, 204},
		{accounts.Role{IsSuperuser: true}, 204},
	} {
		for _, method := range []string{"GET", "HEAD"} {
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error {
				c.Locals("principal", &accounts.Principal{Role: &tc.role})
				return c.Next()
			})
			app.Add([]string{"GET", "HEAD"}, "/", requireAlertChannelOptions, func(c fiber.Ctx) error {
				return c.SendStatus(204)
			})
			response, err := app.Test(httptest.NewRequest(method, "/", nil))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("%s role %+v: got %d want %d", method, tc.role, response.StatusCode, tc.status)
			}
		}
	}
	s := &Server{}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerAlertChannelOptions(app)
	response, err := app.Test(httptest.NewRequest("GET", "/alerts/channels/options/", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("anonymous request: %d", response.StatusCode)
	}
}

func TestAlertChannelOptionsSafeResponse(t *testing.T) {
	for _, tc := range []struct {
		rows []alertChannelOption
		want string
	}{
		{[]alertChannelOption{}, `[]`},
		{[]alertChannelOption{{ID: 1, Name: "Disabled", Enabled: false}}, `[{"id":1,"name":"Disabled","enabled":false}]`},
	} {
		data, err := json.Marshal(tc.rows)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != tc.want {
			t.Fatalf("got %s, want %s", data, tc.want)
		}
	}
}
