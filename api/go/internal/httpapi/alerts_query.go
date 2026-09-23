package httpapi

import (
	"bytes"
	"encoding/json"
	"math"
	"time"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerAlertQueries(app *fiber.App) {
	app.Patch("/alerts/", s.authenticate, s.queryAlerts)
}

type alertAgentNames struct {
	AgentID  *string
	Hostname *string
	Site     *string
	Client   *string
}

// Shared AlertSerializer projection for detail and list; missing agent-derived
// ReadOnlyFields are omitted, while nullable model fields remain JSON null.
func serializeAlertRow(row map[string]any, agent alertAgentNames) (map[string]any, error) {
	renameAlertFields(row, "agent", "assigned_check", "assigned_task")
	if agent.AgentID != nil {
		row["agent_id"], row["hostname"], row["site"], row["client"] = agent.AgentID, agent.Hostname, agent.Site, agent.Client
	}
	for _, field := range []string{"alert_time", "snooze_until", "resolved_on", "email_sent", "resolved_email_sent", "sms_sent", "resolved_sms_sent", "action_run", "resolved_action_run"} {
		if text, ok := row[field].(string); ok {
			parsed, err := time.Parse(time.RFC3339Nano, text)
			if err != nil {
				return nil, err
			}
			row[field] = datetime(&parsed)
		}
	}
	return row, nil
}

func alertQueryValue(raw json.RawMessage) any {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	_ = decoder.Decode(&value) // jsonObject already checked the complete JSON body.
	return value
}

func alertQueryInteger(raw json.RawMessage) (int64, bool) {
	value := alertQueryValue(raw)
	if number, ok := value.(json.Number); ok {
		if n, err := number.Int64(); err == nil {
			return n, true
		}
		if jsonType(raw) == "int" {
			return 0, false
		}
		n, err := number.Float64()
		if err != nil || math.IsInf(n, 0) || n < -9223372036854775808.0 || n >= 9223372036854775808.0 {
			return 0, false
		}
	}
	return pyInt(value)
}

func (s *Server) queryAlerts(c fiber.Ctx) error {
	if !principal(c).Can("can_list_alerts") {
		return errForbidden()
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	query := db.Table("alerts_alert al").
		Joins("LEFT JOIN agents_agent a ON a.id = al.agent_id LEFT JOIN clients_site s ON s.id = a.site_id LEFT JOIN clients_client cl ON cl.id = s.client_id")
	p := principal(c)
	if !p.User.IsSuperuser && (p.Role == nil || !p.Role.IsSuperuser) {
		query = agentScope(query, c).Or("al.agent_id IS NULL AND al.assigned_check_id IS NULL AND al.assigned_task_id IS NULL")
	}
	// Group the role OR predicates before adding the common hidden/filter clauses.
	allowed := query.Select("al.id")
	query = db.Table("alerts_alert al").
		Joins("LEFT JOIN agents_agent a ON a.id = al.agent_id LEFT JOIN clients_site s ON s.id = a.site_id LEFT JOIN clients_client cl ON cl.id = s.client_id").
		Where("al.id IN (?)", allowed).Where("NOT al.hidden")
	var count int64
	top, dashboard := input["top"]
	if dashboard {
		limit, ok := alertQueryInteger(top)
		if !ok || limit < 0 {
			return validationError{"top": {"A non-negative integer is required."}}
		}
		query = query.Where("NOT al.resolved AND NOT al.snoozed")
		if err := query.Count(&count).Error; err != nil {
			return err
		}
		query = query.Order("al.alert_time, al.id").Limit(int(limit))
	} else {
		for _, filter := range []struct{ key, column string }{{"resolvedFilter", "al.resolved"}, {"snoozedFilter", "al.snoozed"}} {
			raw, exists := input[filter.key]
			if !exists {
				continue
			}
			value := alertQueryValue(raw)
			if pyTruthy(value) {
				continue
			}
			switch value.(type) {
			case nil:
				query = query.Where(filter.column + " IS NULL")
			case bool, json.Number:
				query = query.Where(filter.column + " = FALSE")
			default:
				return validationError{filter.key: {"A boolean or null is required."}}
			}
		}
		if raw, exists := input["clientFilter"]; exists {
			var items []json.RawMessage
			if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
				return validationError{"clientFilter": {"Expected a list of client IDs."}}
			}
			ids := []int64{}
			for _, item := range items {
				if jsonType(item) == "NoneType" {
					continue
				}
				id, ok := alertQueryInteger(item)
				if !ok {
					return validationError{"clientFilter": {"A valid client ID is required."}}
				}
				ids = append(ids, id)
			}
			query = query.Where("s.client_id IN ?", ids)
		}
		if raw, exists := input["severityFilter"]; exists {
			var items []json.RawMessage
			if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
				return validationError{"severityFilter": {"Expected a list of severities."}}
			}
			severities := []string{}
			for _, item := range items {
				if jsonType(item) == "NoneType" {
					continue
				}
				// CharField query preparation casts scalars to strings without enforcing choices.
				switch jsonType(item) {
				case "str", "int", "float", "bool":
					severities = append(severities, pyStr(alertQueryValue(item)))
				default:
					return validationError{"severityFilter": {"Expected severity strings."}}
				}
			}
			query = query.Where("al.severity IN ?", severities)
		}
		if raw, exists := input["timeFilter"]; exists {
			days, ok := alertQueryInteger(raw)
			if !ok || days < -3652059 || days > 3652059 {
				return validationError{"timeFilter": {"A valid number of days is required."}}
			}
			now := time.Now().UTC()
			lower := now.AddDate(0, 0, -int(days))
			if lower.Year() < 1 || lower.Year() > 9999 {
				return validationError{"timeFilter": {"Date is out of range."}}
			}
			query = query.Where("al.alert_time <= ? AND al.alert_time > ?", now, lower)
		}
		query = query.Order("al.id")
	}
	rows, err := query.Select("to_jsonb(al), a.agent_id, a.hostname, s.name, cl.name").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var raw []byte
		var agent alertAgentNames
		if err := rows.Scan(&raw, &agent.AgentID, &agent.Hostname, &agent.Site, &agent.Client); err != nil {
			return err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return err
		}
		row, err = serializeAlertRow(row, agent)
		if err != nil {
			return err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if dashboard {
		return c.JSON(fiber.Map{"alerts_count": count, "alerts": out})
	}
	return c.JSON(out)
}
