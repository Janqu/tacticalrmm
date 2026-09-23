package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerPatchPolicyWrites(app *fiber.App) {
	app.Post("/automation/patchpolicy/", s.authenticate, require("can_manage_automation_policies"), s.writePatchPolicy)
	app.Add([]string{fiber.MethodPut, fiber.MethodDelete}, "/automation/patchpolicy/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_automation_policies"), s.writePatchPolicy)
}

func patchPolicyProjection(row map[string]any) map[string]any {
	if row == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range row {
		out[k] = v
	}
	renameAlertFields(out, "agent", "policy")
	return out
}

func patchDaysSpec(raw json.RawMessage) (any, any) {
	if jsonType(raw) == "NoneType" {
		return nil, nil
	}
	var items []json.RawMessage
	if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
		return nil, []string{fmt.Sprintf("Expected a list of items but got type \"%s\".", jsonType(raw))}
	}
	values := make([]any, len(items))
	problems := map[string]any{}
	for i, item := range items {
		value, problem := signedIntSpec(item)
		if problem != nil {
			problems[strconv.Itoa(i)] = problem
		} else {
			values[i] = value
		}
	}

	if len(problems) > 0 {
		return nil, problems
	}
	return values, nil
}

func patchPolicyParsers() map[string]parser {
	p := map[string]parser{"created_by": charSpec(255, true, true), "modified_by": charSpec(255, true, true), "run_time_days": patchDaysSpec, "reprocess_failed_times": posIntSpec}
	for _, key := range []string{"critical", "important", "moderate", "low", "other"} {
		p[key] = choiceSpec("manual", "approve", "ignore", "inherit")
	}
	p["run_time_frequency"] = choiceSpec("daily", "monthly", "inherit")
	p["reboot_after_install"] = choiceSpec("never", "required", "always", "inherit")
	for _, key := range []string{"reprocess_failed_inherit", "reprocess_failed", "email_if_fail"} {
		p[key] = boolSpec
	}
	for key, bounds := range map[string][2]int{"run_time_hour": {0, 23}, "run_time_day": {1, 31}} {
		choices := []string{}
		for i := bounds[0]; i <= bounds[1]; i++ {
			choices = append(choices, strconv.Itoa(i))
		}
		p[key] = func(raw json.RawMessage) (any, any) {
			value, msg := choiceField(raw, choices...)
			if len(msg) > 0 {
				return nil, msg
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, []string{"A valid integer is required."}
			}
			return n, nil
		}
	}
	return p
}

func (s *Server) hasPermOnAgentPK(tx *gorm.DB, c fiber.Ctx, value any) error {
	if value == nil {
		return nil
	}
	var row struct{ AgentID string }
	if err := tx.Table("agents_agent").Select("agent_id").Where("id = ?", value).Take(&row).Error; err != nil {
		return lookupError(err, "Agent")
	}
	return s.hasPermOnAgent(c, row.AgentID)
}

func (s *Server) writePatchPolicy(c fiber.Ctx) error {
	create := c.Method() == fiber.MethodPost
	var id int64
	var err error
	if !create {
		id, err = identifier(c)
		if err != nil {
			return err
		}
		if id == 0 {
			return lookupError(gorm.ErrRecordNotFound, "WinUpdatePolicy")
		}
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before := map[string]any(nil)
		if !create {
			before, err = readRow(tx, "winupdate_winupdatepolicy", id, true)
			if err != nil {
				return lookupError(err, "WinUpdatePolicy")
			}
			if err := s.hasPermOnAgentPK(tx, c, before["agent_id"]); err != nil {
				return err
			}
		}
		name := func(row map[string]any) (string, error) {
			var result struct{ Name string }
			table, column, value := "automation_policy", "name", row["policy_id"]
			if row["agent_id"] != nil {
				table, column, value = "agents_agent", "hostname", row["agent_id"]
			}
			if value == nil {
				return "", validationError{"non_field_errors": {"An agent or automation policy is required."}}
			}
			err := tx.Table(table).Select(column+" AS name").Where("id = ?", value).Take(&result).Error
			return result.Name, err
		}
		if c.Method() == fiber.MethodDelete {
			label, err := name(before)
			if err != nil {
				return err
			}
			if err := tx.Exec("DELETE FROM winupdate_winupdatepolicy WHERE id = ?", id).Error; err != nil {
				return err
			}
			before["id"] = nil
			return coreAudit(tx, c, "UpdatePatchPolicy", "delete", "winupdatepolicy", label, &id, patchPolicyProjection(before), nil, nil)
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		// Django's create view first looks up policy, before serializer validation.
		if create {
			raw, ok := input["policy"]
			if !ok {
				return validationError{"policy": {"This field is required."}}
			}
			pk, msgs := relatedID(raw)
			if len(msgs) > 0 {
				return validationError{"policy": msgs}
			}
			var n int64
			if err := tx.Table("automation_policy").Where("id = ?", pk).Count(&n).Error; err != nil {
				return err
			}
			if n == 0 {
				return lookupError(gorm.ErrRecordNotFound, "Policy")
			}
		}
		values, err := parseFields(input, patchPolicyParsers())
		problems := nestedValidation{}
		if err != nil {
			if !errors.As(err, &problems) {
				return err
			}
			values = map[string]any{}
		}
		for field, table := range map[string]string{"agent": "agents_agent", "policy": "automation_policy"} {
			if raw, ok := input[field]; ok {
				pk, msgs, err := nullableRelation(tx, raw, table)
				if err != nil {
					return err
				}
				if len(msgs) > 0 {
					problems[field] = msgs
				} else if pk == nil {
					values[field+"_id"] = nil
				} else {
					values[field+"_id"] = *pk
				}
			}
		}
		if len(problems) > 0 {
			return problems
		}
		after := defaultWinUpdatePolicy()
		for key, value := range before {
			after[key] = value
		}
		for key, value := range values {
			after[key] = value
		}
		if err := s.hasPermOnAgentPK(tx, c, after["agent_id"]); err != nil {
			return err
		}
		label, err := name(after)
		if err != nil {
			return err
		}
		old, current := patchPolicyProjection(before), patchPolicyProjection(after)
		if create || !jsonEqual(old, current) {
			action := "modify"
			pk := &id
			if create {
				action = "add"
				pk = nil
			}
			if err := coreAudit(tx, c, "UpdatePatchPolicy", action, "winupdatepolicy", label, pk, old, current, nil); err != nil {
				return err
			}
		}
		actor, now := principal(c).User.Username, time.Now().UTC()
		if value, _ := after["created_by"].(string); value == "" {
			after["created_by"] = actor
		}
		after["modified_by"], after["modified_time"] = actor, now
		if create {
			after["created_time"] = now
		}
		columns := []string{"created_by", "modified_by", "modified_time", "agent_id", "policy_id", "critical", "important", "moderate", "low", "other", "run_time_hour", "run_time_frequency", "run_time_days", "run_time_day", "reboot_after_install", "reprocess_failed_inherit", "reprocess_failed", "reprocess_failed_times", "email_if_fail"}
		payload, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if create {
			columns = append(columns, "created_time")
			names := strings.Join(columns, ",")
			return tx.Exec("INSERT INTO winupdate_winupdatepolicy ("+names+") SELECT "+names+" FROM jsonb_populate_record(NULL::winupdate_winupdatepolicy, ?::jsonb)", string(payload)).Error
		}
		sets := []string{}
		for _, column := range columns {
			sets = append(sets, column+" = data."+column)
		}
		return tx.Exec("UPDATE winupdate_winupdatepolicy SET "+strings.Join(sets, ",")+" FROM jsonb_populate_record(NULL::winupdate_winupdatepolicy, ?::jsonb) data WHERE winupdate_winupdatepolicy.id = ?", string(payload), id).Error
	})
	if err != nil {
		return coreError(c, err)
	}
	return c.JSON("ok")
}
