package httpapi

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerPatchPolicyReset(app *fiber.App) {
	app.Post("/automation/patchpolicy/reset/", s.authenticate, require("can_manage_automation_policies"), s.resetPatchPolicy)
}

func resetPatchValues() map[string]any {
	return map[string]any{"critical": "inherit", "important": "inherit", "moderate": "inherit", "low": "inherit", "other": "inherit", "run_time_frequency": "inherit", "reboot_after_install": "inherit", "reprocess_failed_inherit": true}
}

func (s *Server) resetPatchPolicy(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		query := agentScope(tx.Table("agents_agent a").Joins("JOIN clients_site s ON s.id=a.site_id"), c)
		field, raw := "client", input["client"]
		if raw == nil {
			field, raw = "site", input["site"]
		}
		if raw != nil {
			site := field == "site"
			if jsonType(raw) == "NoneType" {
				p := principal(c)
				if !p.User.IsSuperuser && (p.Role == nil || !p.Role.IsSuperuser) {
					label := "Client"
					if site {
						label = "Site"
					}
					return lookupError(gorm.ErrRecordNotFound, label)
				}
				query = query.Where("FALSE")
			} else {
				id, ok := alertQueryInteger(raw)
				if !ok {
					return validationError{field: {"A valid integer is required."}}
				}
				if err := hasPermOnObject(tx, c, site, id); err != nil {
					return err
				}
				column := "s.client_id"
				if site {
					column = "a.site_id"
				}
				query = query.Where(column+" = ?", id)
			}
		}
		var agents []struct {
			ID       int64
			Hostname string
		}
		if err := query.Select("a.id,a.hostname").Order("a.id").Find(&agents).Error; err != nil {
			return err
		}
		for _, agent := range agents {
			rows, err := tx.Raw("SELECT to_jsonb(p) FROM winupdate_winupdatepolicy p WHERE agent_id = ? ORDER BY id FOR UPDATE", agent.ID).Rows()
			if err != nil {
				return err
			}
			policies := []map[string]any{}
			for rows.Next() {
				var raw []byte
				if err := rows.Scan(&raw); err != nil {
					rows.Close()
					return err
				}
				row, err := decodeRow(raw)
				if err != nil {
					rows.Close()
					return err
				}
				policies = append(policies, row)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(policies) != 1 {
				return fmt.Errorf("agent %d requires exactly one patch policy", agent.ID)
			}
			before := patchPolicyProjection(policies[0])
			after := patchPolicyProjection(policies[0])
			values := resetPatchValues()
			for key, value := range values {
				after[key] = value
			}
			if !reflect.DeepEqual(before, after) {
				if err := coreAudit(tx, c, "ResetPatchPolicy", "modify", "winupdatepolicy", agent.Hostname, nil, before, after, nil); err != nil {
					return err
				}
			}
			// Django save(update_fields=...) does not persist audit metadata or auto_now.
			if err := tx.Table("winupdate_winupdatepolicy").Where("id = ?", policies[0]["id"].(json.Number)).Updates(values).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON("The patch policy on the affected agents has been reset.")
}
