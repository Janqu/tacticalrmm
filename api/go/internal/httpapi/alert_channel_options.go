package httpapi

import "github.com/gofiber/fiber/v3"

func (s *Server) registerAlertChannelOptions(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/alerts/channels/options/", s.authenticate, requireAlertChannelOptions, s.alertChannelOptions)
}

func requireAlertChannelOptions(c fiber.Ctx) error {
	for _, permission := range []string{
		"can_list_alerttemplates", "can_manage_alerttemplates", "can_manage_sites", "can_view_core_settings", "can_edit_agent",
	} {
		if principal(c).Can(permission) {
			return c.Next()
		}
	}
	return errForbidden()
}

type alertChannelOption struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

func (s *Server) alertChannelOptions(c fiber.Ctx) error {
	rows := []alertChannelOption{}
	if err := s.DB.WithContext(c.Context()).Table("alerts_matrixchannel").
		Select("id", "name", "enabled").Order("name").Find(&rows).Error; err != nil {
		return err
	}
	return c.JSON(rows)
}
