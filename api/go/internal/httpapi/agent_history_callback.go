package httpapi

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerHistoryCallbacks(app *fiber.App) {
	app.Add([]string{fiber.MethodPatch, fiber.MethodGet, fiber.MethodHead, fiber.MethodPost, fiber.MethodPut, fiber.MethodDelete}, "/api/v3/:pk<regex(^[0-9]+$)>/:agentid/histresult/", s.authenticateAgentCallback, s.historyResultCallback)
}

func historyCallbackResults(input map[string]json.RawMessage) (*string, bool, error) {
	for key := range input {
		if key != "results" {
			return nil, false, validationError{key: {"This field is not supported for command result callbacks."}}
		}
	}
	raw, present := input["results"]
	if !present {
		return nil, false, nil
	}
	value, problems := charField(raw, int(^uint(0)>>1), true, true)
	if len(problems) > 0 {
		return nil, false, validationError{"results": problems}
	}
	return value, true, nil
}

// AgentHistory.script_results is a nullable JSONField, with no nested serializer.
// Preserve JSON numbers and shapes rather than inventing a result schema.
func scriptHistoryCallbackUpdates(input map[string]json.RawMessage) (map[string]any, error) {
	updates := make(map[string]any)
	for key, raw := range input {
		switch key {
		case "results":
			value, problems := charField(raw, int(^uint(0)>>1), true, true)
			if len(problems) > 0 {
				return nil, validationError{key: problems}
			}
			updates[key] = value
		case "script_results":
			if !json.Valid(raw) {
				return nil, validationError{key: {"Value must be valid JSON."}}
			}
			if strings.TrimSpace(string(raw)) == "null" {
				updates[key] = nil
			} else {
				updates[key] = gorm.Expr("?::jsonb", string(raw))
			}
		default:
			return nil, validationError{key: {"This field is not supported for script result callbacks."}}
		}
	}
	return updates, nil
}

func collectorCallbackValue(input map[string]json.RawMessage, all bool) (string, error) {
	var result map[string]json.RawMessage
	if jsonType(input["script_results"]) != "dict" || json.Unmarshal(input["script_results"], &result) != nil {
		return "", validationError{"script_results": {"An object with string stdout is required for collector callbacks."}}
	}
	var stdout string
	if jsonType(result["stdout"]) != "str" || json.Unmarshal(result["stdout"], &stdout) != nil || strings.ContainsRune(stdout, 0) {
		return "", validationError{"script_results": {"A string stdout without null characters is required for collector callbacks."}}
	}
	return scriptCollectorValue(stdout, all)
}

func (s *Server) historyResultCallback(c fiber.Ctx) error {
	if c.Method() != fiber.MethodPatch {
		return fiber.NewError(405, "Method \""+c.Method()+"\" not allowed.")
	}
	// Keep the existing API-wide 4 MiB limit. Django's >10 MiB stdout
	// truncation behavior is intentionally not enabled for this bounded callback.
	if len(c.Body()) > 4*1024*1024 {
		return fiber.NewError(413, "Request Entity Too Large")
	}
	user := c.Locals(agentCallbackPrincipalKey{}).(*accounts.AgentTokenPrincipal)
	if user.AgentID == nil {
		return agentNotFound()
	}
	id, err := url.PathUnescape(c.Params("agentid"))
	if err != nil || strings.Contains(id, "/") {
		return fiber.NewError(404, "Not found.")
	}
	var agent struct{ AgentID string }
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("agent_id").Where("id = ?", *user.AgentID).Take(&agent).Error; err != nil {
		return lookupError(err, "Agent")
	}
	if id != agent.AgentID {
		return agentNotFound()
	}
	pk, err := identifier(c)
	if err != nil {
		return err
	}
	if pk == 0 {
		return lookupError(gorm.ErrRecordNotFound, "AgentHistory")
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; err != nil {
			return err
		}
		// Field deletion locks the field before clearing history references.
		// Discover only an owned history, then use the same lock order.
		var peeks []struct{ CustomFieldID *int64 }
		if err := tx.Table("agents_agenthistory").Select("custom_field_id").Where("id = ? AND agent_id = ?", pk, *user.AgentID).Scan(&peeks).Error; err != nil {
			return err
		}
		if len(peeks) != 1 {
			return lookupError(gorm.ErrRecordNotFound, "AgentHistory")
		}
		fieldBefore := peeks[0].CustomFieldID
		if fieldBefore != nil {
			if _, err := loadCustomField(tx, *fieldBefore, true); err != nil {
				return err
			}
		}
		row, err := readRow(tx, "agents_agenthistory", pk, true)
		if err != nil {
			return lookupError(err, "AgentHistory")
		}
		if pyStr(row["agent_id"]) != pyStr(*user.AgentID) {
			return lookupError(gorm.ErrRecordNotFound, "AgentHistory")
		}
		if fieldBefore == nil && row["custom_field_id"] != nil || fieldBefore != nil && (row["custom_field_id"] == nil || pyStr(row["custom_field_id"]) != pyStr(*fieldBefore)) {
			return fiber.NewError(409, "The collector field changed while processing the callback.")
		}
		if (row["type"] != "cmd_run" && row["type"] != "script_run") || (row["type"] == "cmd_run" && (row["script_id"] != nil || row["custom_field_id"] != nil || row["collector_all_output"] == true || row["save_to_agent_note"] == true)) || (row["save_to_agent_note"] == true && row["custom_field_id"] != nil) {
			return fiber.NewError(501, "Task and combined collector-note callbacks are not supported.")
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		if row["type"] == "script_run" {
			updates, err := scriptHistoryCallbackUpdates(input)
			if err != nil {
				return err
			}
			if row["save_to_agent_note"] == true {
				return completeScriptNote(tx, pk, *user.AgentID, user.UserID, input, updates)
			}
			if row["custom_field_id"] != nil {
				value, err := collectorCallbackValue(input, row["collector_all_output"] == true)
				if err != nil {
					return err
				}
				fieldID, valid := pyInt(row["custom_field_id"])
				if !valid {
					return fiber.NewError(400, "Invalid collector field.")
				}
				collector, err := loadScriptCollector(tx, *user.AgentID, fieldID, false)
				if err != nil {
					return err
				}
				if err := saveScriptCollector(tx, *user.AgentID, collector, value); err != nil {
					return err
				}
			}
			if len(updates) == 0 {
				return nil
			}
			return tx.Table("agents_agenthistory").Where("id = ?", pk).Updates(updates).Error
		}
		result, present, err := historyCallbackResults(input)
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		return tx.Exec("UPDATE agents_agenthistory SET results = ? WHERE id = ?", result, pk).Error
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}
