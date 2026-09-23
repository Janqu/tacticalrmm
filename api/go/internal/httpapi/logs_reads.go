package httpapi

import (
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerLogReads(app *fiber.App) {
	app.Patch("/logs/audit/", s.authenticate, s.auditLogs)
	app.Patch("/logs/debug/", s.authenticate, s.debugLogs)
}

func logSort(raw json.RawMessage, descending bool) (string, error) {
	var column string
	if json.Unmarshal(raw, &column) != nil {
		return "", validationError{"pagination": {"Invalid sort field."}}
	}
	switch column {
	case "id", "username", "agent", "agent_id", "entry_time", "action", "object_type", "message", "before_value", "after_value", "debug_info":
	default:
		return "", validationError{"pagination": {"Invalid sort field."}}
	}
	order := "l." + column
	if descending {
		order += " DESC"
	}
	return order, nil
}

func logPage(raw json.RawMessage, pages int64) int64 {
	value := alertQueryValue(raw)
	if number, ok := value.(json.Number); ok && jsonType(raw) == "float" {
		f, err := number.Float64()
		if err != nil || f != math.Trunc(f) {
			return 1
		}
	}
	page, ok := alertQueryInteger(raw)
	if !ok {
		return 1
	}
	if page < 1 || page > pages {
		return pages
	}
	return page
}

func logStrings(raw json.RawMessage, key string) ([]string, error) {
	var items []json.RawMessage
	if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
		return nil, validationError{key: {"Expected a list."}}
	}
	out := []string{}
	for _, item := range items {
		switch jsonType(item) {
		case "NoneType":
			continue
		case "str", "int", "float", "bool":
			out = append(out, pyStr(alertQueryValue(item)))
		default:
			return nil, validationError{key: {"Expected scalar filter values."}}
		}
	}
	return out, nil
}

// _audit_log_filter gives clients precedence over sites when both are set,
// and includes only NULL (not empty or deleted) agent IDs as unassigned logs.
func auditLogScope(query *gorm.DB, c fiber.Ctx) *gorm.DB {
	p := principal(c)
	if p.User.IsSuperuser || p.Role == nil || p.Role.IsSuperuser {
		return query
	}
	clients := "SELECT client_id FROM accounts_role_can_view_clients WHERE role_id = ?"
	sites := "SELECT site_id FROM accounts_role_can_view_sites WHERE role_id = ?"
	return query.Where("l.agent_id IS NULL OR (NOT EXISTS ("+clients+") AND NOT EXISTS ("+sites+")) OR "+
		"(EXISTS ("+clients+") AND s.client_id IN ("+clients+")) OR "+
		"(NOT EXISTS ("+clients+") AND a.site_id IN ("+sites+"))", p.Role.ID, p.Role.ID, p.Role.ID, p.Role.ID, p.Role.ID, p.Role.ID)
}

func (s *Server) auditLogs(c fiber.Ctx) error {
	if !principal(c).Can("can_view_auditlogs") {
		return errForbidden()
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	pagination, err := subObject(input, "pagination")
	if err != nil {
		return err
	}
	for _, field := range []string{"sortBy", "descending", "rowsPerPage", "page"} {
		if _, ok := pagination[field]; !ok {
			return validationError{"pagination": {field + " is required."}}
		}
	}
	order, err := logSort(pagination["sortBy"], pyTruthy(alertQueryValue(pagination["descending"])))
	if err != nil {
		return err
	}
	size, ok := alertQueryInteger(pagination["rowsPerPage"])
	if !ok || size < 1 {
		return validationError{"pagination": {"rowsPerPage must be a positive integer."}}
	}
	db := s.DB.WithContext(c.Context())
	if err := checkLogTimezone(db); err != nil {
		return err
	}
	query := db.Table("logs_auditlog l").Joins("LEFT JOIN agents_agent a ON a.agent_id = l.agent_id LEFT JOIN clients_site s ON s.id = a.site_id LEFT JOIN clients_client cl ON cl.id = s.client_id")
	// Isolate scope OR terms so request filters cannot bypass them.
	allowed := auditLogScope(query, c).Select("l.id")
	query = db.Table("logs_auditlog l").Joins("LEFT JOIN agents_agent a ON a.agent_id = l.agent_id LEFT JOIN clients_site s ON s.id = a.site_id LEFT JOIN clients_client cl ON cl.id = s.client_id").Where("l.id IN (?)", allowed)
	if raw, exists := input["agentFilter"]; exists {
		ids, err := logStrings(raw, "agentFilter")
		if err != nil {
			return err
		}
		query = query.Where("l.agent_id IN ?", ids)
	} else if raw, exists := input["clientFilter"]; exists {
		var values []json.RawMessage
		if jsonType(raw) != "list" || json.Unmarshal(raw, &values) != nil {
			return validationError{"clientFilter": {"Expected a list of client IDs."}}
		}
		ids := []int64{}
		for _, value := range values {
			if jsonType(value) == "NoneType" {
				continue
			}
			id, ok := alertQueryInteger(value)
			if !ok {
				return validationError{"clientFilter": {"Invalid client ID."}}
			}
			ids = append(ids, id)
		}
		query = query.Where("s.client_id IN ?", ids)
	}
	for _, filter := range []struct{ key, column string }{{"userFilter", "username"}, {"actionFilter", "action"}, {"objectFilter", "object_type"}} {
		if raw, exists := input[filter.key]; exists {
			values, err := logStrings(raw, filter.key)
			if err != nil {
				return err
			}
			query = query.Where("l."+filter.column+" IN ?", values)
		}
	}
	if raw, exists := input["timeFilter"]; exists {
		days := 0.0
		switch v := alertQueryValue(raw).(type) {
		case json.Number:
			days, err = v.Float64()
		case bool:
			if v {
				days = 1
			}
		default:
			return validationError{"timeFilter": {"A numeric number of days is required."}}
		}
		if err != nil || math.IsInf(days, 0) || math.Abs(days) > 3652059 {
			return validationError{"timeFilter": {"Date is out of range."}}
		}
		now := time.Now().UTC()
		whole := math.Trunc(days)
		lower := now.AddDate(0, 0, -int(whole)).Add(-time.Duration((days - whole) * float64(24*time.Hour)))
		if lower.Year() < 1 || lower.Year() > 9999 {
			return validationError{"timeFilter": {"Date is out of range."}}
		}
		query = query.Where("l.entry_time <= ? AND l.entry_time > ?", now, lower)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return err
	}
	pages := int64(1)
	if count > 0 {
		pages = (count-1)/size + 1
	}
	page := logPage(pagination["page"], pages)
	rows, err := query.Select("to_jsonb(l), CASE WHEN s.id IS NULL THEN NULL ELSE to_jsonb(s) || jsonb_build_object('client_name',cl.name) END").Order(order).Order("l.id").Limit(int(size)).Offset(int((page - 1) * size)).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var raw, site []byte
		if err := rows.Scan(&raw, &site); err != nil {
			return err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return err
		}
		if err := logTimestamp(row); err != nil {
			return err
		}
		row["site"] = nil
		if len(site) > 0 {
			nested, err := decodeRow(site)
			if err != nil {
				return err
			}
			renameAlertFields(nested, "client", "server_policy", "workstation_policy", "alert_template")
			row["site"] = nested
		}
		if info, ok := row["debug_info"].(map[string]any); ok {
			if ip, exists := info["ip"]; exists {
				row["ip_address"] = ip
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"audit_logs": out, "total": count})
}

func (s *Server) debugLogs(c fiber.Ctx) error {
	if !principal(c).Can("can_view_debuglogs") {
		return errForbidden()
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	if err := checkLogTimezone(db); err != nil {
		return err
	}
	query := db.Table("logs_debuglog l").Joins("LEFT JOIN agents_agent a ON a.id=l.agent_id LEFT JOIN clients_site s ON s.id=a.site_id")
	p := principal(c)
	if !p.User.IsSuperuser && (p.Role == nil || !p.Role.IsSuperuser) {
		query = agentScope(query, c).Or("l.agent_id IS NULL")
	}
	allowed := query.Select("l.id")
	query = db.Table("logs_debuglog l").Joins("LEFT JOIN agents_agent a ON a.id=l.agent_id").Where("l.id IN (?)", allowed)
	for _, filter := range []struct{ key, column string }{{"logTypeFilter", "l.log_type"}, {"logLevelFilter", "l.log_level"}, {"agentFilter", "a.agent_id"}} {
		if raw, exists := input[filter.key]; exists {
			switch jsonType(raw) {
			case "NoneType":
				query = query.Where(filter.column + " IS NULL")
			case "str", "int", "float", "bool":
				query = query.Where(filter.column+" = ?", pyStr(alertQueryValue(raw)))
			default:
				return validationError{filter.key: {"Expected a scalar filter value."}}
			}
		}
	}
	rows, err := query.Select("to_jsonb(l),a.hostname").Order("l.entry_time DESC,l.id").Limit(1000).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var raw []byte
		var hostname *string
		if err := rows.Scan(&raw, &hostname); err != nil {
			return err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return err
		}
		delete(row, "agent_id")
		if hostname != nil {
			row["agent"] = *hostname
		}
		if err := logTimestamp(row); err != nil {
			return err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(out)
}

func logTimestamp(row map[string]any) error {
	// default_tz is unused by Django's ReadOnlyField: preserve UTC ISO output.
	text, ok := row["entry_time"].(string)
	if !ok {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(text))
	if err != nil {
		return err
	}
	row["entry_time"] = datetime(&parsed)
	return nil
}

// Django constructs this ZoneInfo even though neither serializer uses it.
func checkLogTimezone(db *gorm.DB) error {
	_, err := loadDefaultTimezone(db)
	return err
}

func loadDefaultTimezone(db *gorm.DB) (*time.Location, error) {
	var core struct{ DefaultTimeZone string }
	if err := db.Table("core_coresettings").Select("default_time_zone").Order("id").Take(&core).Error; err != nil {
		return nil, err
	}
	return time.LoadLocation(core.DefaultTimeZone)
}
