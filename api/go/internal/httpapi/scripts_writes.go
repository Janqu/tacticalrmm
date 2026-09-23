package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

var scriptFields = []string{"name", "description", "shell", "args", "category", "favorite", "script_body", "default_timeout", "syntax", "filename", "hidden", "supported_platforms", "run_as_user", "env_vars"}

func scriptBodySpec(raw json.RawMessage) (any, any) {
	value, problem := charSpec(unlimited, false, true)(raw)
	if problem == nil && jsonType(raw) == "str" {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, []string{"Not a valid string."}
		}
		return text, nil // Script bodies preserve indentation and terminal newlines.
	}
	return value, problem
}

func scriptArraySpec(platforms bool) parser {
	return func(raw json.RawMessage) (any, any) {
		kind := jsonType(raw)
		if kind == "NoneType" {
			return nil, nil
		}
		var items []json.RawMessage
		if kind != "list" || json.Unmarshal(raw, &items) != nil {
			return nil, []string{fmt.Sprintf("Expected a list of items but got type \"%s\".", kind)}
		}
		max := unlimited
		if platforms {
			max = 20
		}
		values, problems := make([]any, len(items)), map[string][]string{}
		for i, item := range items {
			value, messages := charField(item, max, !platforms, !platforms)
			if len(messages) > 0 {
				problems[fmt.Sprint(i)] = messages
			} else if value != nil {
				values[i] = *value
			}
		}
		if len(problems) > 0 {
			return nil, problems
		}
		return values, nil
	}
}

func scriptParsers() map[string]parser {
	return map[string]parser{
		"name": charSpec(255, false, false), "description": charSpec(unlimited, true, true),
		"shell": choiceSpec("powershell", "cmd", "python", "shell", "nushell", "deno"),
		"args":  scriptArraySpec(false), "env_vars": scriptArraySpec(false), "supported_platforms": scriptArraySpec(true),
		"category": charSpec(100, true, true), "favorite": boolSpec, "hidden": boolSpec, "run_as_user": boolSpec,
		"script_body": scriptBodySpec, "default_timeout": posIntSpec, "syntax": charSpec(unlimited, true, true), "filename": charSpec(255, true, true),
	}
}

func scriptProjection(row map[string]any) map[string]any {
	out := map[string]any{"id": row["id"], "script_hash": row["script_hash"]}
	for _, field := range scriptFields {
		out[field] = row[field]
	}
	return out
}

func readScriptForWrite(tx *gorm.DB, id int64) (map[string]any, error) {
	var raw []byte
	err := tx.Raw("SELECT to_jsonb(t) FROM scripts_script t WHERE id = ? FOR UPDATE", id).Row().Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, gorm.ErrRecordNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeRow(raw)
}

func (s *Server) registerScriptWrites(app *fiber.App) {
	app.Post("/scripts/", s.authenticate, require("can_manage_scripts"), s.writeScript)
	app.Put("/scripts/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_scripts"), s.writeScript)
	app.Delete("/scripts/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_scripts"), s.removeScript)
}

func (s *Server) writeScript(c fiber.Ctx) error {
	create := c.Method() == fiber.MethodPost
	var id int64
	var err error
	if !create {
		id, err = identifier(c)
		if err != nil {
			return err
		}
	}
	name := ""
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var before map[string]any
		if !create {
			before, err = readScriptForWrite(tx, id)
			if err != nil {
				return lookupError(err, "Script")
			}
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		if before["script_type"] == "builtin" {
			if value, ok := input["favorite"]; ok {
				input = map[string]json.RawMessage{"favorite": value}
			} else if value, ok := input["hidden"]; ok {
				input = map[string]json.RawMessage{"hidden": value}
			} else {
				return scriptWriteError("Community scripts cannot be edited.")
			}
		}
		values, err := parseFields(input, scriptParsers())
		if err != nil {
			return err
		}
		after := map[string]any{"id": nil, "name": "", "description": "", "shell": "powershell", "script_type": "userdefined", "args": []any{}, "env_vars": []any{}, "supported_platforms": []any{}, "favorite": false, "hidden": false, "run_as_user": false, "default_timeout": 90, "script_body": "", "code_base64": ""}
		for key, value := range before {
			after[key] = value
		}
		for key, value := range values {
			after[key] = value
		}
		name, _ = after["name"].(string)
		old, current := scriptProjection(before), scriptProjection(after)
		// JSON normalization equates decoded database numbers with parsed int64s.
		oldJSON, _ := json.Marshal(old)
		currentJSON, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if create || string(oldJSON) != string(currentJSON) {
			action, view := "modify", "GetUpdateDeleteScript"
			var pk *int64 = &id
			if create {
				action, view, pk, old = "add", "GetAddScripts", nil, nil
			}
			if err := coreAudit(tx, c, view, action, "script", name, pk, old, current, nil); err != nil {
				return err
			}
		}
		now, actor := time.Now().UTC(), principal(c).User.Username
		if text, _ := after["created_by"].(string); text == "" {
			after["created_by"] = actor
		}
		after["modified_by"], after["modified_time"] = actor, now
		columns := append(append([]string{}, scriptFields...), "created_by", "modified_by", "modified_time")
		if create {
			after["created_time"] = now
			columns = append(columns, "created_time", "script_type", "code_base64")
		}
		payload, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if create {
			names := strings.Join(columns, ",")
			return tx.Exec("INSERT INTO scripts_script ("+names+") SELECT "+names+" FROM jsonb_populate_record(NULL::scripts_script, ?::jsonb)", string(payload)).Error
		}
		set := make([]string, len(columns))
		for i, column := range columns {
			set[i] = column + " = data." + column
		}
		if err := tx.Exec("UPDATE scripts_script SET "+strings.Join(set, ",")+" FROM jsonb_populate_record(NULL::scripts_script, ?::jsonb) data WHERE scripts_script.id = ?", string(payload), id).Error; err != nil {
			return err
		}
		var hasPolicy bool
		if err := tx.Raw("SELECT EXISTS(SELECT 1 FROM checks_check WHERE script_id = ? AND policy_id IS NOT NULL)", id).Scan(&hasPolicy).Error; err != nil {
			return err
		}
		if hasPolicy {
			return s.clearScriptPolicyCache(c.Context())
		}
		return nil
	})
	var message scriptWriteError
	if errors.As(err, &message) {
		return c.Status(400).JSON(string(message))
	}
	if err != nil {
		return coreError(c, err)
	}
	verb := "edited"
	if create {
		verb = "added"
	}
	return c.JSON(fmt.Sprintf("%s was %s!", name, verb))
}

type scriptWriteError string

func (e scriptWriteError) Error() string { return string(e) }

func (s *Server) clearScriptPolicyCache(ctx context.Context) error {
	if s.Cache == nil {
		return errors.New("script policy cache is not configured")
	}
	// Same namespace as core.utils.clear_entire_cache; never touch sessions or Celery.
	for _, pattern := range []string{":1:role_*", ":1:agent_*", ":1:site_*", ":1:throttle_*", ":1:core_settings"} {
		keys, err := s.Cache.Keys(ctx, pattern).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := s.Cache.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) removeScript(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	name := ""
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := readScriptForWrite(tx, id)
		if err != nil {
			return lookupError(err, "Script")
		}
		if before["script_type"] == "builtin" {
			return scriptWriteError("Community scripts cannot be deleted")
		}
		name, _ = before["name"].(string)
		// Django's collector cascades rows without invoking child delete overrides.
		for _, query := range []string{
			"DELETE FROM alerts_matrixdelivery WHERE alert_id IN (SELECT id FROM alerts_alert WHERE assigned_check_id IN (SELECT id FROM checks_check WHERE script_id = ?))",
			"UPDATE qdt_snmp_snmpalert SET alert_id = NULL WHERE alert_id IN (SELECT id FROM alerts_alert WHERE assigned_check_id IN (SELECT id FROM checks_check WHERE script_id = ?))",
			"DELETE FROM alerts_alert WHERE assigned_check_id IN (SELECT id FROM checks_check WHERE script_id = ?)",
			"DELETE FROM checks_checkresult WHERE assigned_check_id IN (SELECT id FROM checks_check WHERE script_id = ?)",
			"UPDATE autotasks_automatedtask SET assigned_check_id = NULL WHERE assigned_check_id IN (SELECT id FROM checks_check WHERE script_id = ?)",
			"DELETE FROM checks_check WHERE script_id = ?",
			"UPDATE agents_agenthistory SET script_id = NULL WHERE script_id = ?",
			"UPDATE alerts_alerttemplate SET action_id = NULL WHERE action_id = ?",
			"UPDATE alerts_alerttemplate SET resolved_action_id = NULL WHERE resolved_action_id = ?",
			"DELETE FROM scripts_script WHERE id = ?",
		} {
			if err := tx.Exec(query, id).Error; err != nil {
				return err
			}
		}
		before["id"] = nil
		return coreAudit(tx, c, "GetUpdateDeleteScript", "delete", "script", name, &id, scriptProjection(before), nil, nil)
	})
	var message scriptWriteError
	if errors.As(err, &message) {
		return c.Status(400).JSON(string(message))
	}
	if err != nil {
		return err
	}
	return c.JSON(name + " was deleted!")
}
