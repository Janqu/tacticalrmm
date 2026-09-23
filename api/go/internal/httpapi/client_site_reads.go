package httpapi

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// ClientSiteRow is exported so GORM discovers its embedded fields.
type ClientSiteRow struct {
	ID                     int64           `json:"id"`
	Name                   string          `json:"name"`
	ServerPolicy           *int64          `json:"server_policy" gorm:"column:server_policy_id"`
	WorkstationPolicy      *int64          `json:"workstation_policy" gorm:"column:workstation_policy_id"`
	AlertTemplate          *int64          `json:"alert_template" gorm:"column:alert_template_id"`
	BlockPolicyInheritance bool            `json:"block_policy_inheritance"`
	FailingChecks          json.RawMessage `json:"failing_checks"`
	CustomFields           json.RawMessage `json:"custom_fields"`
	AgentCount             *int64          `json:"agent_count,omitempty"`
	MaintenanceMode        *bool           `json:"maintenance_mode,omitempty"`
}

type clientReadRow struct {
	ClientSiteRow `gorm:"embedded"`
	Sites         []siteReadRow `json:"sites" gorm:"-"`
}

type siteReadRow struct {
	ClientSiteRow `gorm:"embedded"`
	Client        int64  `json:"client" gorm:"column:client_id"`
	ClientName    string `json:"client_name"`
}

// List scoping is the union of allowed clients and sites. Django's client
// detail permission deliberately checks only the client restriction.
func clientSiteScope(db *gorm.DB, c fiber.Ctx, client, detail bool) *gorm.DB {
	p := principal(c)
	if p.User.IsSuperuser || (p.Role != nil && p.Role.IsSuperuser) {
		return db
	}
	if p.Role == nil {
		return db.Where("FALSE")
	}
	clients := "SELECT client_id FROM accounts_role_can_view_clients WHERE role_id = ?"
	sites := "SELECT site_id FROM accounts_role_can_view_sites WHERE role_id = ?"
	if client && detail {
		return db.Where("NOT EXISTS ("+clients+") OR x.id IN ("+clients+")", p.Role.ID, p.Role.ID)
	}
	clientMatch, siteMatch := "x.client_id", "x.id"
	if client {
		clientMatch = "x.id"
		sites = "SELECT client_id FROM clients_site WHERE id IN (" + sites + ")"
	}
	unrestricted := `NOT EXISTS (` + clients + `) AND NOT EXISTS (
		SELECT site_id FROM accounts_role_can_view_sites WHERE role_id = ?)`
	allowed := clientMatch + " IN (" + clients + ") OR " + siteMatch + " IN (" + sites + ")"
	return db.Where("("+unrestricted+") OR "+allowed, p.Role.ID, p.Role.ID, p.Role.ID, p.Role.ID)
}

// PostgreSQL converts arrays and nullable field values without losing their
// JSON type; only the serializer's public fields are projected.
func clientSiteFields(client bool) string {
	kind := "site"
	if client {
		kind = "client"
	}
	return fmt.Sprintf(`x.*, COALESCE((
		SELECT jsonb_agg(jsonb_build_object(
			'id', v.id, 'field', v.field_id, '%[1]s', v.%[1]s_id,
			'value', CASE f.type
				WHEN 'multiple' THEN to_jsonb(v.multiple_value)
				WHEN 'checkbox' THEN to_jsonb(v.bool_value)
				ELSE to_jsonb(v.string_value) END) ORDER BY v.id)
		FROM clients_%[1]scustomfield v
		JOIN core_customfield f ON f.id = v.field_id
		WHERE v.%[1]s_id = x.id
	), '[]'::jsonb) AS custom_fields`, kind)
}

func (s *Server) readClients(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	query := db.Table("clients_client x")
	detail := c.Params("pk") != ""
	if detail {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		query = query.Where("x.id = ?", id)
	} else {
		query = clientSiteScope(query, c, true, false)
	}
	fields := clientSiteFields(true)
	if !detail {
		fields += `, (SELECT count(*) FROM agents_agent a
			JOIN clients_site t ON t.id = a.site_id
			WHERE t.client_id = x.id) AS agent_count,
			EXISTS (SELECT 1 FROM agents_agent a
			JOIN clients_site t ON t.id = a.site_id
			WHERE t.client_id = x.id AND a.maintenance_mode) AS maintenance_mode`
	}
	rows := []clientReadRow{}
	if err := query.Select(fields).Order("x.name").Find(&rows).Error; err != nil {
		return err
	}
	if detail {
		if len(rows) == 0 {
			return lookupError(gorm.ErrRecordNotFound, "Client")
		}
		if c.Method() == fiber.MethodGet {
			var allowed int64
			if err := clientSiteScope(db.Table("clients_client x").Where("x.id = ?", rows[0].ID), c, true, true).Count(&allowed).Error; err != nil {
				return err
			}
			if allowed == 0 {
				return fiber.NewError(403, "You do not have permission to perform this action.")
			}
		}
	}
	ids := make([]int64, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
		rows[i].Sites = []siteReadRow{}
	}
	if len(ids) > 0 {
		sites := []siteReadRow{}
		query := clientSiteScope(db.Table("clients_site x"), c, false, false).Where("x.client_id IN ?", ids)
		fields := clientSiteFields(false) + `, parent.name AS client_name,
			(SELECT count(*) FROM agents_agent a WHERE a.site_id = x.id) AS agent_count,
			EXISTS (SELECT 1 FROM agents_agent a
			WHERE a.site_id = x.id AND a.maintenance_mode) AS maintenance_mode`
		if err := query.Joins("JOIN clients_client parent ON parent.id = x.client_id").Select(fields).Order("x.name").Find(&sites).Error; err != nil {
			return err
		}
		byClient := make(map[int64][]siteReadRow)
		for _, site := range sites {
			byClient[site.Client] = append(byClient[site.Client], site)
		}
		for i := range rows {
			if sites := byClient[rows[i].ID]; sites != nil {
				rows[i].Sites = sites
			}
		}
	}
	if detail {
		return c.JSON(rows[0])
	}
	return c.JSON(rows)
}

func (s *Server) readSites(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	query := db.Table("clients_site x")
	detail := c.Params("pk") != ""
	if detail {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		query = query.Where("x.id = ?", id)
	} else {
		query = clientSiteScope(query, c, false, false)
	}
	rows := []siteReadRow{}
	if err := query.Joins("JOIN clients_client parent ON parent.id = x.client_id").Select(clientSiteFields(false) + ", parent.name AS client_name").Order("x.name").Find(&rows).Error; err != nil {
		return err
	}
	if detail {
		if len(rows) == 0 {
			return lookupError(gorm.ErrRecordNotFound, "Site")
		}
		if c.Method() == fiber.MethodGet {
			var allowed int64
			if err := clientSiteScope(db.Table("clients_site x").Where("x.id = ?", rows[0].ID), c, false, true).Count(&allowed).Error; err != nil {
				return err
			}
			if allowed == 0 {
				return fiber.NewError(403, "You do not have permission to perform this action.")
			}
		}
		return c.JSON(rows[0])
	}
	return c.JSON(rows)
}
