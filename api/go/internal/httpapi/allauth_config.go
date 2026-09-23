package httpapi

import "github.com/gofiber/fiber/v3"

// allauthConfig supplies the login page's capability discovery contract. Go
// supports local account login; provider redirects are not implemented yet.
func (s *Server) allauthConfig(c fiber.Ctx) error {
	c.Set("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate, private")
	return c.JSON(fiber.Map{
		"status": fiber.StatusOK,
		"data": fiber.Map{
			"account": fiber.Map{
				"authentication_method":              "username",
				"is_open_for_signup":                 false,
				"email_verification_by_code_enabled": false,
				"login_by_code_enabled":              false,
			},
			"socialaccount": fiber.Map{"providers": []string{}},
		},
	})
}
