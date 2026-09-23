package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerWinUpdates(app *fiber.App) {
	app.Put("/winupdate/bulk/", s.authenticate, require("can_manage_winupdates"), s.bulkWinUpdates)
	app.Put("/winupdate/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_winupdates"), s.writeWinUpdate)
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/winupdate/:agent_id/", s.authenticate, require("can_manage_winupdates"), s.readWinUpdates)
}

func (s *Server) readWinUpdates(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	tz, err := loadDefaultTimezone(db)
	if err != nil {
		return err
	}
	rows, err := db.Raw("SELECT to_jsonb(w) FROM winupdate_winupdate w WHERE agent_id = ? ORDER BY id DESC, installed", pk).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return err
		}
		renameAlertFields(row, "agent")
		if value, ok := row["date_installed"].(string); ok {
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return err
			}
			row["date_installed"] = at.In(tz).Format("01 02 2006 15:04")
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(out)
}

func winUpdateArray(raw json.RawMessage) (any, any) {
	value, problem := scriptArraySpec(false)(raw)
	if problem != nil || value == nil {
		return value, problem
	}
	problems := map[string][]string{}
	for i, item := range value.([]any) {
		if text, ok := item.(string); ok && utf8.RuneCountInString(text) > 255 {
			problems[fmt.Sprint(i)] = []string{"Ensure this field has no more than 255 characters."}
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return value, nil
}

func winUpdateParsers() map[string]parser {
	p := map[string]parser{"installed": boolSpec, "downloaded": boolSpec, "result": charSpec(255, false, false), "action": choiceSpec("inherit", "approve", "ignore", "nothing")}
	for _, key := range []string{"guid", "severity"} {
		p[key] = charSpec(255, true, true)
	}
	p["title"] = charSpec(unlimited, true, true)
	p["kb"] = charSpec(100, true, true)
	p["description"] = charSpec(unlimited, true, true)
	p["support_url"] = charSpec(unlimited, true, true)
	p["more_info_urls"] = scriptArraySpec(false)
	for _, key := range []string{"categories", "category_ids", "kb_article_ids"} {
		p[key] = winUpdateArray
	}
	p["revision_number"] = func(raw json.RawMessage) (any, any) {
		if jsonType(raw) == "NoneType" {
			return nil, nil
		}
		return signedIntSpec(raw)
	}
	return p
}

func (s *Server) writeWinUpdate(c fiber.Ctx) error {
	// Django's 21+-character agent converter precedes its integer PK route.
	if len(c.Params("pk")) >= 21 {
		return fiber.NewError(405, `Method "PUT" not allowed.`)
	}
	id, err := identifier(c)
	if err != nil {
		return err
	}
	if id == 0 {
		return lookupError(gorm.ErrRecordNotFound, "WinUpdate")
	}
	var message string
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := readRow(tx, "winupdate_winupdate", id, true)
		if err != nil {
			return lookupError(err, "WinUpdate")
		}
		if err := s.hasPermOnAgentPK(tx, c, before["agent_id"]); err != nil {
			return err
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		values, err := parseFields(input, winUpdateParsers())
		problems := nestedValidation{}
		if err != nil {
			if !errors.As(err, &problems) {
				return err
			}
			values = map[string]any{}
		}
		if raw, ok := input["agent"]; ok {
			if jsonType(raw) == "NoneType" {
				problems["agent"] = []string{"This field may not be null."}
			} else {
				pk, msgs, err := nullableRelation(tx, raw, "agents_agent")
				if err != nil {
					return err
				}
				if len(msgs) > 0 {
					problems["agent"] = msgs
				} else {
					values["agent_id"] = *pk
				}
			}
		}
		if len(problems) > 0 {
			return problems
		}
		if target, ok := values["agent_id"]; ok {
			if err := s.hasPermOnAgentPK(tx, c, target); err != nil {
				return err
			}
		}
		for key, value := range values {
			before[key] = value
		}
		// WinUpdate is a plain Model: no audit entry or agent execution accompanies approval.
		if len(values) > 0 {
			columns := []string{}
			for key := range values {
				columns = append(columns, key+" = data."+key)
			}
			data, err := json.Marshal(before)
			if err != nil {
				return err
			}
			if err := tx.Exec("UPDATE winupdate_winupdate SET "+strings.Join(columns, ",")+" FROM jsonb_populate_record(NULL::winupdate_winupdate, ?::jsonb) data WHERE winupdate_winupdate.id = ?", string(data), id).Error; err != nil {
				return err
			}
		}
		kb := "None"
		if before["kb"] != nil {
			kb = fmt.Sprint(before["kb"])
		}
		message = fmt.Sprintf("Windows update %s was changed to %s", kb, before["action"])
		return nil
	})
	if err != nil {
		return coreError(c, err)
	}
	return c.JSON(message)
}

func (s *Server) bulkWinUpdates(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	raw, ok := input["action"]
	if !ok {
		return c.Status(400).JSON("Invalid action")
	}
	action, messages := choiceField(raw, "inherit", "approve", "ignore", "nothing")
	if len(messages) > 0 {
		return c.Status(400).JSON("Invalid action")
	}
	raw, ok = input["pks"]
	if !ok || jsonType(raw) == "NoneType" {
		return c.Status(400).JSON("No patches were selected")
	}
	var items []json.RawMessage
	if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
		return c.Status(400).JSON(fiber.Map{"pks": []string{"Expected a list of patch IDs."}})
	}
	if len(items) == 0 {
		return c.Status(400).JSON("No patches were selected")
	}
	ids := make([]int64, len(items))
	for i, item := range items {
		pk, msg := relatedID(item)
		if len(msg) > 0 {
			return c.Status(400).JSON(fiber.Map{"pks": msg})
		}
		ids[i] = pk
	}
	var count int64
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		allowed := agentScope(tx.Table("winupdate_winupdate w").Joins("JOIN agents_agent a ON a.id=w.agent_id JOIN clients_site s ON s.id=a.site_id"), c).Where("w.id IN ?", ids).Select("w.id")
		if principal(c).User.IsInstallerUser {
			allowed = allowed.Where("FALSE")
		}
		result := tx.Table("winupdate_winupdate").Where("id IN (?)", allowed).Update("action", action)
		count = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return err
	}
	return c.JSON(fmt.Sprintf("%d patch(es) were changed to %s", count, action))
}
