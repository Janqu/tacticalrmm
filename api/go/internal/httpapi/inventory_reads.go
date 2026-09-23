package httpapi

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerInventoryReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	app.Add(read, "/qdt_inventory/assets/", s.authenticate, inventoryReadPermission, s.inventoryAssets)
	app.Add(read, "/qdt_inventory/profiles/", s.authenticate, inventoryReadPermission, s.inventoryProfiles)
	app.Add(read, "/qdt_inventory/options/", s.authenticate, inventoryReadPermission, s.inventoryOptions)
}

func inventoryReadPermission(c fiber.Ctx) error {
	p := principal(c)
	if p.User.IsInstallerUser || (!p.Can("can_list_sites") && !p.Can("can_manage_sites")) {
		return errForbidden()
	}
	return c.Next()
}

type inventoryProfile struct {
	ID               int64           `json:"id"`
	Client           int64           `json:"client" gorm:"column:client_id"`
	Name             string          `json:"name"`
	Category         string          `json:"category"`
	Manufacturer     string          `json:"manufacturer"`
	ModelName        string          `json:"model_name"`
	DocumentationURL string          `json:"documentation_url"`
	Notes            string          `json:"notes"`
	Defaults         json.RawMessage `json:"defaults"`
	Version          int64           `json:"version"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

func (s *Server) inventoryProfiles(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	sites := clientSiteScope(db.Table("clients_site x"), c, false, false).Select("x.client_id")
	profiles := []inventoryProfile{}
	err := db.Table("qdt_inventory_deviceprofile").
		Select("id, client_id, name, category, manufacturer, model_name, documentation_url, notes, defaults, version, updated_at").
		Where("client_id IN (?)", sites).Order("name, id").Find(&profiles).Error
	if err != nil {
		return err
	}
	return c.JSON(profiles)
}

func (s *Server) inventoryOptions(c fiber.Ctx) error {
	type inventorySite struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		ClientID   int64  `json:"client_id"`
		ClientName string `json:"client_name"`
	}
	sites := []inventorySite{}
	query := s.DB.WithContext(c.Context()).Table("clients_site x").Joins("JOIN clients_client parent ON parent.id=x.client_id")
	err := clientSiteScope(query, c, false, false).
		Select("x.id, x.name, x.client_id, parent.name AS client_name").Order("parent.name, x.name").Find(&sites).Error
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"can_manage": principal(c).Can("can_manage_sites"),
		"sites":      sites,
		"categories": []string{"computer", "server", "printer", "network", "ups", "nas", "display", "phone", "projector", "rack", "cable", "power_supply", "other"},
		"states":     []string{"planned", "stock", "active", "repair", "retired", "disposed"},
	})
}
