package httpapi

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

type alertActionError string

func (e alertActionError) Error() string { return string(e) }

func (s *Server) registerAlertWrites(app *fiber.App) {
	app.Add([]string{fiber.MethodPut, fiber.MethodDelete}, "/alerts/:pk<regex(^[0-9]+$)>/", s.authenticate, s.writeAlert)
	app.Post("/alerts/bulk/", s.authenticate, s.bulkAlerts)
}

func (s *Server) alertAgentPermission(tx *gorm.DB, c fiber.Ctx, pk any) error {
	if pk == nil {
		return nil
	}
	var id string
	if err := tx.Table("agents_agent").Select("agent_id").Where("id = ?", pk).Scan(&id).Error; err != nil {
		return err
	}
	return s.hasPermOnAgent(c, id)
}

func (s *Server) writeAlert(c fiber.Ctx) error {
	if !principal(c).Can("can_manage_alerts") {
		return errForbidden()
	}
	id, err := identifier(c)
	if err != nil {
		return err
	}
	if id == 0 {
		return lookupError(gorm.ErrRecordNotFound, "Alert")
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := readRow(tx, "alerts_alert", id, true)
		if err != nil {
			return lookupError(err, "Alert")
		}
		if err := s.alertAgentPermission(tx, c, before["agent_id"]); err != nil {
			return err
		}
		if c.Method() == fiber.MethodDelete {
			// Django's collector performs these actions in application code, rather
			// than PostgreSQL ON DELETE clauses. Keep the entire deletion atomic.
			if err := tx.Exec("DELETE FROM alerts_matrixdelivery WHERE alert_id = ?", id).Error; err != nil {
				return err
			}
			if err := tx.Exec("UPDATE qdt_snmp_snmpalert SET alert_id = NULL WHERE alert_id = ?", id).Error; err != nil {
				return err
			}
			return tx.Exec("DELETE FROM alerts_alert WHERE id = ?", id).Error
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		values, err := s.alertUpdateValues(tx, c, input)
		if err != nil {
			return err
		}
		if len(values) == 0 {
			return nil
		}
		// Updating an existing Alert has no audit or notification hook in Django.
		return tx.Table("alerts_alert").Where("id = ?", id).Updates(values).Error
	})
	if problem, ok := err.(alertActionError); ok {
		return c.Status(400).JSON(string(problem))
	}
	if err != nil {
		return coreError(c, err)
	}
	return c.JSON("ok")
}

func (s *Server) alertUpdateValues(tx *gorm.DB, c fiber.Ctx, input map[string]json.RawMessage) (map[string]any, error) {
	if raw, ok := input["type"]; ok {
		var action string
		_ = json.Unmarshal(raw, &action)
		switch action {
		case "resolve":
			return map[string]any{"resolved": true, "resolved_on": time.Now().UTC(), "snoozed": false, "snooze_until": nil}, nil
		case "unsnooze":
			return map[string]any{"snoozed": false, "snooze_until": nil}, nil
		case "snooze":
			if _, ok := input["snooze_days"]; !ok {
				return nil, alertActionError("Missing 'snoozed_days' when trying to snooze alert")
			}
			until, err := alertSnoozeUntil(input["snooze_days"])
			if err != nil {
				return nil, err
			}
			return map[string]any{"snoozed": true, "snooze_until": until}, nil
		default:
			return nil, alertActionError("There was an error in the request data")
		}
	}
	parsers := map[string]parser{
		"alert_type": choiceSpec("availability", "check", "task", "custom"),
		"severity":   choiceSpec("info", "warning", "error"),
		"message":    charSpec(unlimited, true, true),
		"snoozed":    boolSpec, "resolved": boolSpec, "hidden": boolSpec,
	}
	for _, prefix := range []string{"action", "resolved_action"} {
		parsers[prefix+"_stdout"] = charSpec(unlimited, true, true)
		parsers[prefix+"_stderr"] = charSpec(unlimited, true, true)
		parsers[prefix+"_execution_time"] = charSpec(100, true, true)
		parsers[prefix+"_retcode"] = alertRetcode
	}
	for _, field := range []string{"snooze_until", "resolved_on", "email_sent", "resolved_email_sent", "sms_sent", "resolved_sms_sent", "action_run", "resolved_action_run"} {
		parsers[field] = func(raw json.RawMessage) (any, any) {
			value, errors := datetimeField(raw)
			if len(errors) > 0 {
				return nil, errors
			}
			return value, nil
		}
	}
	values, err := parseFields(input, parsers)
	problems := nestedValidation{}
	if err != nil {
		problems = err.(nestedValidation)
	}
	for _, relation := range []struct{ field, table string }{{"agent", "agents_agent"}, {"assigned_check", "checks_check"}, {"assigned_task", "autotasks_automatedtask"}} {
		raw, exists := input[relation.field]
		if !exists {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) == nil && text == "" {
			raw = json.RawMessage("null")
		}
		target, messages, err := nullableRelation(tx, raw, relation.table)
		if err != nil {
			return nil, err
		}
		if len(messages) > 0 {
			problems[relation.field] = messages
			continue
		}
		if values == nil {
			values = map[string]any{}
		}
		values[relation.field+"_id"] = target
	}
	if len(problems) > 0 {
		return nil, problems
	}
	// Django only checks the old agent. Also authorize each new relation so an
	// allowed alert cannot be used to modify a different customer's objects.
	for _, relation := range []struct{ field, table string }{{"agent_id", "agents_agent"}, {"assigned_check_id", "checks_check"}, {"assigned_task_id", "autotasks_automatedtask"}} {
		target, ok := values[relation.field].(*int64)
		if !ok || target == nil {
			continue
		}
		var agent any = *target
		if relation.field != "agent_id" {
			var related struct{ AgentID *int64 }
			if err := tx.Table(relation.table).Select("agent_id").Where("id = ?", *target).Scan(&related).Error; err != nil {
				return nil, err
			}
			if related.AgentID == nil {
				continue
			}
			agent = *related.AgentID
		}
		if err := s.alertAgentPermission(tx, c, agent); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// DRF's nullable BigIntegerField accepts integer-valued strings and numbers.
func alertRetcode(raw json.RawMessage) (any, any) {
	if jsonType(raw) == "NoneType" {
		return nil, nil
	}
	text := string(raw)
	if jsonType(raw) == "str" {
		_ = json.Unmarshal(raw, &text)
		if utf8.RuneCountInString(text) > 1000 {
			return nil, []string{"String value too large."}
		}
	}
	text = strings.TrimSpace(text)
	if dot := strings.LastIndex(text, "."); dot >= 0 && strings.Trim(text[dot+1:], "0") == "" {
		text = text[:dot]
	}
	number, ok := new(big.Int).SetString(text, 10)
	if !ok && jsonType(raw) == "float" {
		if n, err := strconv.ParseFloat(text, 64); err == nil && n == math.Trunc(n) {
			number, _ = new(big.Float).SetFloat64(n).Int(nil)
			ok = number != nil
		}
	}
	if !ok {
		return nil, []string{"A valid integer is required."}
	}
	if number.Cmp(big.NewInt(math.MinInt64)) < 0 {
		return nil, []string{"Ensure this value is greater than or equal to -9223372036854775808."}
	}
	if number.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return nil, []string{"Ensure this value is less than or equal to 9223372036854775807."}
	}
	return number.Int64(), nil
}

func alertSnoozeUntil(raw json.RawMessage) (time.Time, error) {
	text := string(raw)
	var days int64
	var err error
	switch jsonType(raw) {
	case "str":
		_ = json.Unmarshal(raw, &text)
		days, err = strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	case "bool":
		if text == "true" {
			days = 1
		}
	case "int":
		days, err = strconv.ParseInt(text, 10, 64)
	case "float":
		var value float64
		value, err = strconv.ParseFloat(text, 64)
		if err == nil && math.Abs(value) < 3652059 {
			days = int64(value)
		} else {
			err = fmt.Errorf("invalid days")
		}
	default:
		err = fmt.Errorf("invalid days")
	}
	// Bound before AddDate so int conversion and date arithmetic cannot overflow.
	if err != nil || days < -3652059 || days > 3652059 {
		return time.Time{}, validationError{"snooze_days": {"A valid number of days is required."}}
	}
	until := time.Now().UTC().AddDate(0, 0, int(days))
	if until.Year() < 1 || until.Year() > 9999 {
		return time.Time{}, validationError{"snooze_days": {"Snooze date is out of range."}}
	}
	return until, nil
}

func (s *Server) bulkAlerts(c fiber.Ctx) error {
	if !principal(c).Can("can_manage_alerts") {
		return errForbidden()
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	var action string
	_ = json.Unmarshal(input["bulk_action"], &action)
	values := map[string]any{}
	switch action {
	case "resolve":
		values = map[string]any{"resolved": true, "resolved_on": time.Now().UTC(), "snoozed": false, "snooze_until": nil}
	case "snooze":
		if _, ok := input["snooze_days"]; !ok {
			return c.Status(400).JSON("The request was invalid")
		}
		until, err := alertSnoozeUntil(input["snooze_days"])
		if err != nil {
			return err
		}
		values = map[string]any{"snoozed": true, "snooze_until": until}
	default:
		return c.Status(400).JSON("The request was invalid")
	}
	var rawIDs []json.RawMessage
	if jsonType(input["alerts"]) != "list" || json.Unmarshal(input["alerts"], &rawIDs) != nil {
		return validationError{"alerts": {"Expected a list of alert IDs."}}
	}
	ids := make([]int64, 0, len(rawIDs))
	for _, raw := range rawIDs {
		id, messages := relatedID(raw)
		if len(messages) > 0 {
			return validationError{"alerts": messages}
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return c.JSON("ok")
	}
	db := s.DB.WithContext(c.Context())
	allowed := db.Table("alerts_alert al").Select("al.id").Joins("LEFT JOIN agents_agent a ON a.id = al.agent_id LEFT JOIN clients_site s ON s.id = a.site_id")
	p := principal(c)
	if !p.User.IsSuperuser && (p.Role == nil || !p.Role.IsSuperuser) {
		allowed = agentScope(allowed, c).Or("al.agent_id IS NULL AND al.assigned_check_id IS NULL AND al.assigned_task_id IS NULL")
	}
	// A single UPDATE preserves all-or-nothing semantics and leaves disallowed
	// IDs untouched, like PermissionQuerySet.filter_by_role(Alert).
	if err := db.Table("alerts_alert").Where("id IN ?", ids).Where("id IN (?)", allowed).Updates(values).Error; err != nil {
		return err
	}
	return c.JSON("ok")
}
