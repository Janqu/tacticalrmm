package httpapi

import (
	"encoding/json"
	"strings"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerAlertReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	pk := ":pk<regex(^[0-9]+$)>"
	app.Add(read, "/alerts/templates/", s.authenticate, s.readAlertTemplates)
	app.Add(read, "/alerts/templates/"+pk+"/", s.authenticate, s.readAlertTemplates)
	app.Add(read, "/alerts/templates/"+pk+"/related/", s.authenticate, s.readAlertTemplates)
	app.Add(read, "/alerts/"+pk+"/", s.authenticate, s.readAlert)
}

func alertReadPermission(c fiber.Ctx, list, manage string) error {
	permission := list
	if c.Method() != fiber.MethodGet {
		permission = manage
	}
	if !principal(c).Can(permission) {
		return errForbidden()
	}
	return nil
}

func renameAlertFields(row map[string]any, fields ...string) {
	for _, field := range fields {
		row[field] = row[field+"_id"]
		delete(row, field+"_id")
	}
}

// The serializers expose every model field. Use the same row decoder as the
// existing core reads, then add the explicit many-to-many and computed fields.
// ponytail: per-template queries suit small configuration lists; batch relations
// if installations grow to thousands of templates.
func (s *Server) readAlertTemplates(c fiber.Ctx) error {
	if err := alertReadPermission(c, "can_list_alerttemplates", "can_manage_alerttemplates"); err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	var rows []map[string]any
	var err error
	if c.Params("pk") != "" {
		id, problem := identifier(c)
		if problem != nil {
			return problem
		}
		if id == 0 {
			return lookupError(gorm.ErrRecordNotFound, "AlertTemplate")
		}
		row, problem := readRow(db, "alerts_alerttemplate", id, false)
		if problem != nil {
			return lookupError(problem, "AlertTemplate")
		}
		rows = []map[string]any{row}
	} else {
		rows, err = listRows(db, "alerts_alerttemplate")
		if err != nil {
			return err
		}
	}
	related := strings.HasSuffix(c.Path(), "/related/")
	for _, row := range rows {
		id := row["id"]
		renameAlertFields(row, "action", "action_rest", "resolved_action", "resolved_action_rest")
		for _, relation := range []struct{ field, target string }{
			{"matrix_channels", "matrixchannel"}, {"excluded_clients", "client"},
			{"excluded_sites", "site"}, {"excluded_agents", "agent"},
		} {
			ids := []int64{}
			query := db.Table("alerts_alerttemplate_"+relation.field+" r").Where("r.alerttemplate_id = ?", id)
			if relation.target == "client" || relation.target == "site" {
				query = query.Joins("JOIN clients_" + relation.target + " t ON t.id = r." + relation.target + "_id").Order("t.name")
			} else if relation.target == "agent" {
				query = query.Order("r.agent_id")
			} else {
				query = query.Order("r." + relation.target + "_id")
			}
			if err := query.Pluck("r."+relation.target+"_id", &ids).Error; err != nil {
				return err
			}
			row[relation.field] = ids
		}
		if related {
			if err := alertTemplateRelations(db, row); err != nil {
				return err
			}
			continue
		}
		for _, kind := range []string{"agent", "check", "task"} {
			enabled := false
			for _, suffix := range []string{"email_on_resolved", "text_on_resolved", "always_email", "always_text", "always_alert", "periodic_alert_days", "email_alert_severity", "text_alert_severity", "dashboard_alert_severity"} {
				enabled = enabled || alertTruthy(row[kind+"_"+suffix])
			}
			row[kind+"_settings"] = enabled
		}
		// Python's `or` returns the recipient array, not just a bool.
		row["core_settings"] = any(false)
		switch {
		case alertTruthy(row["email_from"]):
			row["core_settings"] = true
		case alertTruthy(row["email_recipients"]):
			row["core_settings"] = row["email_recipients"]
		case alertTruthy(row["text_recipients"]):
			row["core_settings"] = row["text_recipients"]
		default:
			row["core_settings"] = len(row["matrix_channels"].([]int64)) > 0
		}
		var count int64
		if err := db.Table("core_coresettings").Where("alert_template_id = ?", id).Count(&count).Error; err != nil {
			return err
		}
		row["default_template"] = count > 0
		count = 0
		for _, table := range []string{"automation_policy", "clients_client", "clients_site"} {
			var n int64
			if err := db.Table(table).Where("alert_template_id = ?", id).Count(&n).Error; err != nil {
				return err
			}
			count += n
		}
		row["applied_count"] = count
		for _, prefix := range []string{"action", "resolved_action"} {
			table, fk := "scripts_script", row[prefix]
			if row[prefix+"_type"] == "rest" && row[prefix+"_rest"] != nil {
				table, fk = "core_urlaction", row[prefix+"_rest"]
			}
			name := ""
			if fk != nil {
				if err := db.Table(table).Select("name").Where("id = ?", fk).Scan(&name).Error; err != nil {
					return err
				}
			}
			row[prefix+"_name"] = name
		}
	}
	if c.Params("pk") != "" {
		return c.JSON(rows[0])
	}
	return c.JSON(rows)
}

func alertTruthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		return x != "0"
	case []any:
		return len(x) > 0
	}
	return false
}

func alertTemplateRelations(db *gorm.DB, row map[string]any) error {
	for _, relation := range []struct{ field, table string }{{"policies", "automation_policy"}, {"clients", "clients_client"}, {"sites", "clients_site"}} {
		order := "id"
		if relation.field != "policies" {
			order = "name"
		}
		rawRows, err := db.Raw("SELECT to_jsonb(t) FROM "+relation.table+" t WHERE alert_template_id = ? ORDER BY "+order, row["id"]).Rows()
		if err != nil {
			return err
		}
		entries := []map[string]any{}
		for rawRows.Next() {
			var raw []byte
			if err := rawRows.Scan(&raw); err != nil {
				rawRows.Close()
				return err
			}
			entry, err := decodeRow(raw)
			if err != nil {
				rawRows.Close()
				return err
			}
			entries = append(entries, entry)
		}
		err = rawRows.Err()
		rawRows.Close()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			renameAlertFields(entry, "alert_template")
			if relation.field == "policies" {
				for _, target := range []struct{ field, column string }{{"excluded_clients", "client_id"}, {"excluded_sites", "site_id"}, {"excluded_agents", "agent_id"}} {
					ids := []int64{}
					query := db.Table("automation_policy_"+target.field+" r").Where("r.policy_id = ?", entry["id"])
					if target.column != "agent_id" {
						query = query.Joins("JOIN clients_" + strings.TrimSuffix(target.column, "_id") + " t ON t.id = r." + target.column).Order("t.name")
					} else {
						query = query.Order("r.agent_id")
					}
					if err := query.Pluck("r."+target.column, &ids).Error; err != nil {
						return err
					}
					entry[target.field] = ids
				}
			} else {
				renameAlertFields(entry, "server_policy", "workstation_policy")
				if relation.field == "sites" {
					renameAlertFields(entry, "client")
					name := ""
					if err := db.Table("clients_client").Select("name").Where("id = ?", entry["client"]).Scan(&name).Error; err != nil {
						return err
					}
					entry["client_name"] = name
				}
			}
		}
		row[relation.field] = entries
	}
	return nil
}

func (s *Server) readAlert(c fiber.Ctx) error {
	if err := alertReadPermission(c, "can_list_alerts", "can_manage_alerts"); err != nil {
		return err
	}
	id, err := identifier(c)
	if err != nil {
		return err
	}
	if id == 0 {
		return lookupError(gorm.ErrRecordNotFound, "Alert")
	}
	db := s.DB.WithContext(c.Context())
	row, err := readRow(db, "alerts_alert", id, false)
	if err != nil {
		return lookupError(err, "Alert")
	}
	var agent alertAgentNames
	if row["agent_id"] != nil {
		if err := db.Table("agents_agent a").Select("a.agent_id, a.hostname, s.name AS site, c.name AS client").
			Joins("JOIN clients_site s ON s.id = a.site_id JOIN clients_client c ON c.id = s.client_id").
			Where("a.id = ?", row["agent_id"]).Scan(&agent).Error; err != nil {
			return err
		}
		if agent.AgentID == nil {
			return agentNotFound()
		}
		if err := s.hasPermOnAgent(c, *agent.AgentID); err != nil {
			return err
		}
	}
	row, err = serializeAlertRow(row, agent)
	if err != nil {
		return err
	}
	return c.JSON(row)
}
