package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
)

func TestAgentInstallerUnavailable(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name      string
		principal *accounts.Principal
		status    int
	}{
		{"anonymous", nil, 401},
		{"without permission", &accounts.Principal{}, 403},
		{"administrator", &accounts.Principal{User: accounts.User{IsSuperuser: true}}, 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
			if tc.principal == nil {
				// Exercise the actual registration/authentication chain without credentials.
				s.registerAgentInstaller(app)
			} else {
				app.Post("/agents/installer/", func(c fiber.Ctx) error {
					c.Locals("principal", tc.principal)
					return c.Next()
				}, require("can_install_agents"), s.agentInstaller)
			}
			response, err := app.Test(httptest.NewRequest("POST", "/agents/installer/", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, tc.status)
			}
			if tc.status == 501 {
				var message string
				if err := json.NewDecoder(response.Body).Decode(&message); err != nil {
					t.Fatal(err)
				}
				if message != "Agent-Installer und Registrierung sind in der Go-Testumgebung noch nicht verfügbar." {
					t.Fatalf("unexpected installer response: %q", message)
				}
			}
		})
	}
}
