package httpapi

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
)

func TestInventoryReadPermissions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p      *accounts.Principal
		status int
	}{
		{"no role", &accounts.Principal{}, 403},
		{"agents only", &accounts.Principal{Role: &accounts.Role{CanListAgents: true}}, 403},
		{"site reader", &accounts.Principal{Role: &accounts.Role{CanListSites: true}}, 204},
		{"site manager", &accounts.Principal{Role: &accounts.Role{CanManageSites: true}}, 204},
		{"superuser", &accounts.Principal{User: accounts.User{IsSuperuser: true}}, 204},
		{"installer", &accounts.Principal{User: accounts.User{IsSuperuser: true, IsInstallerUser: true}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error { c.Locals("principal", tc.p); return c.Next() })
			app.Add([]string{"GET", "HEAD"}, "/", inventoryReadPermission, func(c fiber.Ctx) error { return c.SendStatus(204) })
			for _, method := range []string{"GET", "HEAD"} {
				response, err := app.Test(httptest.NewRequest(method, "/", nil))
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != tc.status {
					t.Fatalf("%s: got %d want %d", method, response.StatusCode, tc.status)
				}
			}
		})
	}
}

func TestInventoryReadRoutesRejectAnonymous(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerInventoryReads(app)
	for _, path := range []string{"/qdt_inventory/profiles/", "/qdt_inventory/options/", "/qdt_inventory/assets/"} {
		response, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatalf("%s: got %d", path, response.StatusCode)
		}
	}
}
