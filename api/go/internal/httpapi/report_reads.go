package httpapi

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerReportReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	app.Add(read, "/qdt_reports/options/", s.authenticate, requireReportRead, s.reportOptions)
	app.Add(read, "/qdt_reports/configurations/", s.authenticate, requireReportRead, s.reportConfigurations)
	app.Add(read, "/qdt_reports/client/:pk<regex(^[0-9]+$)>/health/", s.authenticate, requireReportRead, s.reportHealth)
}

func requireReportRead(c fiber.Ctx) error {
	p := principal(c)
	if p.User.IsInstallerUser || (!p.Can("can_view_reports") && !p.Can("can_manage_reports")) {
		return errForbidden()
	}
	return c.Next()
}

type reportSiteOption struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type reportClientOption struct {
	ID    int64              `json:"id"`
	Name  string             `json:"name"`
	Sites []reportSiteOption `json:"sites"`
}

type reportSiteRow struct {
	ID         int64
	Name       string
	ClientID   int64
	ClientName string
}

func reportClientOptions(rows []reportSiteRow) []reportClientOption {
	clients := []reportClientOption{}
	index := make(map[int64]int)
	for _, row := range rows {
		i, found := index[row.ClientID]
		if !found {
			i = len(clients)
			index[row.ClientID] = i
			clients = append(clients, reportClientOption{ID: row.ClientID, Name: row.ClientName, Sites: []reportSiteOption{}})
		}
		clients[i].Sites = append(clients[i].Sites, reportSiteOption{ID: row.ID, Name: row.Name})
	}
	return clients
}

func (s *Server) reportOptions(c fiber.Ctx) error {
	rows := []reportSiteRow{}
	query := clientSiteScope(s.DB.WithContext(c.Context()).Table("clients_site x"), c, false, false)
	if err := query.Joins("JOIN clients_client parent ON parent.id = x.client_id").
		Select("x.id, x.name, x.client_id, parent.name AS client_name").
		Order("parent.name, x.name").Find(&rows).Error; err != nil {
		return err
	}
	return c.JSON(fiber.Map{"clients": reportClientOptions(rows), "can_manage": principal(c).Can("can_manage_reports")})
}

type reportConfigurationRow struct {
	ID            int64
	Name          string
	Configuration json.RawMessage
	UpdatedAt     time.Time
}

// The nested DRF serializer exposes only known options, applying defaults on
// reads as well as writes. site_id remains omitted when it was not specified.
func reportConfigurationOptions(raw json.RawMessage) (map[string]any, error) {
	stored := map[string]any{}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, err
	}
	options := map[string]any{
		"ram_below_gb": 8, "disk_free_below_percent": 10, "software_query": "",
		"monitoring_type": "all", "patch_days": 30, "client_id": nil,
	}
	for _, field := range []string{"template", "ram_below_gb", "disk_free_below_percent", "software_query", "site_id", "monitoring_type", "patch_days", "client_id", "sections"} {
		if value, present := stored[field]; present {
			options[field] = value
		}
	}
	return options, nil
}

func (s *Server) reportConfigurations(c fiber.Ctx) error {
	rows := []reportConfigurationRow{}
	if err := s.DB.WithContext(c.Context()).Table("qdt_reports_reportconfiguration").
		Select("id", "name", "configuration", "updated_at").
		Where("owner_id = ?", principal(c).User.ID).Order("name, id").Find(&rows).Error; err != nil {
		return err
	}
	result := []fiber.Map{}
	for _, row := range rows {
		configuration, err := reportConfigurationOptions(row.Configuration)
		if err != nil {
			return err
		}
		result = append(result, fiber.Map{
			"id": row.ID, "name": row.Name, "configuration": configuration, "updated_at": datetime(&row.UpdatedAt),
		})
	}
	return c.JSON(result)
}
