package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) registerWinUpdateCallbacks(app *fiber.App) {
	methods := []string{fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodGet, fiber.MethodHead, fiber.MethodDelete}
	app.Add(methods, "/api/v3/winupdates/", s.authenticateAgentCallback, s.winUpdatesCallback)
	app.Add(methods, "/api/v3/superseded/", s.authenticateAgentCallback, s.supersededCallback)
}

type scanUpdate struct {
	Fields map[string]any
	Skip   bool
}

func scanString(raw json.RawMessage, max int) (any, error) {
	if jsonType(raw) == "NoneType" {
		return nil, nil
	}
	var value string
	if jsonType(raw) != "str" || json.Unmarshal(raw, &value) != nil {
		return nil, fmt.Errorf("a string or null is required")
	}
	if strings.ContainsRune(value, 0) || utf8.RuneCountInString(value) > max {
		return nil, fmt.Errorf("invalid string length or character")
	}
	return value, nil
}

func scanGUID(input map[string]json.RawMessage) (any, error) {
	raw, ok := input["guid"]
	if !ok {
		return nil, validationError{"guid": {"This field is required."}}
	}
	value, err := scanString(raw, 255)
	if err != nil {
		return nil, validationError{"guid": {"A string of at most 255 characters or null is required."}}
	}
	return value, nil
}
func guidKey(value any) string {
	if value == nil {
		return "null"
	}
	return "str:" + value.(string)
}

// Plan every update before touching rows. Metadata is required only for rows
// which will be created; existing GUIDs only carry the two state flags.
func planScanUpdates(raw json.RawMessage, known map[string]bool) ([]scanUpdate, []any, error) {
	var updates []map[string]json.RawMessage
	if jsonType(raw) != "list" || json.Unmarshal(raw, &updates) != nil {
		return nil, nil, validationError{"wua_updates": {"Expected a list of update objects."}}
	}
	plan := []scanUpdate{}
	returned := []any{}
	for _, input := range updates {
		guid, err := scanGUID(input)
		if err != nil {
			return nil, nil, err
		}
		returned = append(returned, guid)
		fields := map[string]any{"guid": guid}
		existing := known[guidKey(guid)]
		if !existing {
			// Django deliberately skips new updates without a usable first KB entry.
			var kb []json.RawMessage
			if json.Unmarshal(input["kb_article_ids"], &kb) != nil || len(kb) == 0 || jsonType(kb[0]) != "str" {
				plan = append(plan, scanUpdate{Skip: true})
				continue
			}
			var number string
			_ = json.Unmarshal(kb[0], &number)
			if utf8.RuneCountInString("KB"+number) > 100 || strings.ContainsRune(number, 0) {
				return nil, nil, validationError{"kb_article_ids": {"Invalid KB identifier."}}
			}
			fields["kb"] = "KB" + number
		}
		for _, key := range []string{"installed", "downloaded"} {
			var value bool
			if jsonType(input[key]) != "bool" || json.Unmarshal(input[key], &value) != nil {
				return nil, nil, validationError{key: {"A boolean is required."}}
			}
			fields[key] = value
		}
		if !existing {
			for _, key := range []string{"title", "description", "severity", "support_url"} {
				value, present := input[key]
				if !present {
					return nil, nil, validationError{key: {"This field is required."}}
				}
				maximum := unlimited
				if key == "severity" {
					maximum = 255
				}
				text, err := scanString(value, maximum)
				if err != nil {
					return nil, nil, validationError{key: {"Invalid string value."}}
				}
				fields[key] = text
			}
			for _, key := range []string{"categories", "category_ids", "kb_article_ids", "more_info_urls"} {
				value, present := input[key]
				if !present {
					return nil, nil, validationError{key: {"This field is required."}}
				}
				if jsonType(value) == "NoneType" {
					fields[key] = nil
					continue
				}
				var entries []json.RawMessage
				if jsonType(value) != "list" || json.Unmarshal(value, &entries) != nil {
					return nil, nil, validationError{key: {"Expected a list or null."}}
				}
				parsed := []any{}
				for _, entry := range entries {
					maximum := 255
					if key == "more_info_urls" {
						maximum = unlimited
					}
					text, err := scanString(entry, maximum)
					if err != nil {
						return nil, nil, validationError{key: {"Invalid array element."}}
					}
					parsed = append(parsed, text)
				}
				fields[key] = parsed
			}
			revision, present := input["revision_number"]
			if !present {
				return nil, nil, validationError{"revision_number": {"This field is required."}}
			}
			fields["revision_number"] = nil
			if jsonType(revision) != "NoneType" {
				var number int64
				if jsonType(revision) != "int" || json.Unmarshal(revision, &number) != nil || number < -2147483648 || number > 2147483647 {
					return nil, nil, validationError{"revision_number": {"A 32-bit integer or null is required."}}
				}
				fields["revision_number"] = number
			}
			fields["action"] = "nothing"
			fields["result"] = "n/a"
			fields["date_installed"] = nil
			known[guidKey(guid)] = true
		}
		plan = append(plan, scanUpdate{Fields: fields})
	}
	return plan, returned, nil
}

func lockCallbackAgent(tx *gorm.DB, agentPK int64) error {
	var agent struct{ ID int64 }
	return lookupError(tx.Table("agents_agent").Select("id").Where("id = ?", agentPK).Clauses(clause.Locking{Strength: "UPDATE"}).Take(&agent).Error, "Agent")
}

func (s *Server) winUpdatesCallback(c fiber.Ctx) error {
	if c.Method() == fiber.MethodPatch {
		return s.winUpdateResultCallback(c)
	}
	if c.Method() == fiber.MethodPut {
		return s.winUpdateCompletionCallback(c)
	}
	if c.Method() != fiber.MethodPost {
		return fiber.NewError(405, "Method \""+c.Method()+"\" not allowed.")
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	raw, present := input["wua_updates"]
	if !present {
		return validationError{"wua_updates": {"This field is required."}}
	}
	if !pyTruthy(alertQueryValue(raw)) {
		return c.Status(400).JSON("Empty payload")
	}
	user := c.Locals(agentCallbackPrincipalKey{}).(*accounts.AgentTokenPrincipal)
	if user.AgentID == nil {
		return agentNotFound()
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		pk := *user.AgentID
		if err := lockCallbackAgent(tx, pk); err != nil {
			return err
		}
		var current []struct {
			ID   int64
			GUID *string
		}
		if err := tx.Table("winupdate_winupdate").Select("id,guid").Where("agent_id = ?", pk).Order("id").Find(&current).Error; err != nil {
			return err
		}
		known := map[string]bool{}
		ids := map[string]int64{}
		for _, row := range current {
			var guid any
			if row.GUID != nil {
				guid = *row.GUID
			}
			key := guidKey(guid)
			known[key] = true
			ids[key] = row.ID
		}
		plan, returned, err := planScanUpdates(raw, known)
		if err != nil {
			return err
		}
		for _, update := range plan {
			if update.Skip {
				continue
			}
			fields := update.Fields
			key := guidKey(fields["guid"])
			if id, exists := ids[key]; exists {
				if err := tx.Table("winupdate_winupdate").Where("id = ?", id).Updates(map[string]any{"downloaded": fields["downloaded"], "installed": fields["installed"]}).Error; err != nil {
					return err
				}
			} else {
				fields["agent_id"] = pk
				encoded, err := json.Marshal(fields)
				if err != nil {
					return err
				}
				const columns = "agent_id,guid,kb,title,installed,downloaded,description,severity,categories,category_ids,kb_article_ids,more_info_urls,support_url,revision_number,action,result,date_installed"
				var id int64
				if err := tx.Raw("INSERT INTO winupdate_winupdate ("+columns+") SELECT "+columns+" FROM jsonb_populate_record(NULL::winupdate_winupdate, ?::jsonb) RETURNING id", string(encoded)).Scan(&id).Error; err != nil {
					return err
				}
				ids[key] = id
			}
		}
		// NOT IN must retain Django's NULL handling: a returned null does not protect
		// existing null GUIDs from exclude(guid__in=...).
		nonnull := []any{}
		for _, guid := range returned {
			if guid != nil {
				nonnull = append(nonnull, guid)
			}
		}
		stale := tx.Where("agent_id = ? AND installed = false", pk)
		if len(nonnull) > 0 {
			stale = stale.Where("(guid IS NULL OR guid NOT IN ?)", nonnull)
		}
		if err := stale.Table("winupdate_winupdate").Delete(map[string]any{}).Error; err != nil {
			return err
		}
		return pruneSupersededUpdates(tx, pk)
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func (s *Server) supersededCallback(c fiber.Ctx) error {
	if c.Method() != fiber.MethodPost {
		return fiber.NewError(405, "Method \""+c.Method()+"\" not allowed.")
	}
	user := c.Locals(agentCallbackPrincipalKey{}).(*accounts.AgentTokenPrincipal)
	if user.AgentID == nil {
		return agentNotFound()
	}
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		pk := *user.AgentID
		if err := lockCallbackAgent(tx, pk); err != nil {
			return err
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		guid, err := scanGUID(input)
		if err != nil {
			return err
		}
		query := tx.Table("winupdate_winupdate").Where("agent_id = ?", pk)
		if guid == nil {
			query = query.Where("guid IS NULL")
		} else {
			query = query.Where("guid = ?", guid)
		}
		return query.Delete(map[string]any{}).Error
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func winUpdateSuccess(input map[string]json.RawMessage) (bool, error) {
	var success bool
	if jsonType(input["success"]) != "bool" || json.Unmarshal(input["success"], &success) != nil {
		return false, validationError{"success": {"A boolean is required."}}
	}
	return success, nil
}

func (s *Server) winUpdateResultCallback(c fiber.Ctx) error {
	user := c.Locals(agentCallbackPrincipalKey{}).(*accounts.AgentTokenPrincipal)
	if user.AgentID == nil {
		return agentNotFound()
	}
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		pk := *user.AgentID
		if err := lockCallbackAgent(tx, pk); err != nil {
			return err
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		guid, err := scanGUID(input)
		if err != nil {
			return err
		}
		var update struct{ ID int64 }
		query := tx.Table("winupdate_winupdate").Select("id").Where("agent_id = ?", pk)
		if guid == nil {
			query = query.Where("guid IS NULL")
		} else {
			query = query.Where("guid = ?", guid)
		}
		if err := query.Order("id DESC").Clauses(clause.Locking{Strength: "UPDATE"}).Take(&update).Error; err != nil {
			return lookupError(err, "WinUpdate")
		}
		success, err := winUpdateSuccess(input)
		if err != nil {
			return err
		}
		fields := map[string]any{"result": "failed"}
		if success {
			fields = map[string]any{"result": "success", "downloaded": true, "installed": true, "date_installed": time.Now().UTC()}
		}
		if err := tx.Table("winupdate_winupdate").Where("id = ?", update.ID).Updates(fields).Error; err != nil {
			return err
		}
		return pruneSupersededUpdates(tx, pk)
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func updateCompletionReboot(policy any, needsReboot bool) bool {
	return policy == "always" || (policy == "required" && needsReboot)
}

// Only completion branches without a remote reboot are implemented. A callback
// has no execution identity, so reboot requests cannot safely be deduplicated.
func (s *Server) winUpdateCompletionCallback(c fiber.Ctx) error {
	user := c.Locals(agentCallbackPrincipalKey{}).(*accounts.AgentTokenPrincipal)
	if user.AgentID == nil {
		return agentNotFound()
	}
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		pk := *user.AgentID
		if err := lockCallbackAgent(tx, pk); err != nil {
			return err
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		var needsReboot bool
		if jsonType(input["needs_reboot"]) != "bool" || json.Unmarshal(input["needs_reboot"], &needsReboot) != nil {
			return validationError{"needs_reboot": {"A boolean is required."}}
		}
		var agent struct{ AgentID string }
		if err := tx.Table("agents_agent").Select("agent_id").Where("id = ?", pk).Take(&agent).Error; err != nil {
			return lookupError(err, "Agent")
		}
		// Agent callbacks do not establish Django request audit context.
		policy, err := effectiveWinUpdatePolicy(tx, agent.AgentID, nil)
		if err != nil {
			return err
		}
		if updateCompletionReboot(policy["reboot_after_install"], needsReboot) {
			return fiber.NewError(501, "Windows update completion requiring a reboot is not implemented.")
		}
		if err := tx.Table("agents_agent").Where("id = ?", pk).Update("needs_reboot", needsReboot).Error; err != nil {
			return err
		}
		return pruneSupersededUpdates(tx, pk)
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}
