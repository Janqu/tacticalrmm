package httpapi

import "github.com/gofiber/fiber/v3"

func (s *Server) registerAgentInstaller(app *fiber.App) {
	app.Post("/agents/installer/", s.authenticate, require("can_install_agents"), s.agentInstaller)
}

func (s *Server) agentInstaller(c fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON("Agent-Installer und Registrierung sind in der Go-Testumgebung noch nicht verfügbar.")
}
