package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerCheckReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	pk := ":pk<regex(^[0-9]+$)>"
	for _, path := range []string{"/checks/", "/checks/" + pk + "/", "/automation/policies/:policy<regex(^[0-9]+$)>/checks/"} {
		app.Add(read, path, s.authenticate, requireRead("can_list_checks", "can_manage_checks"), s.readChecks)
	}
	app.Patch("/checks/"+pk+"/history/", s.authenticate, require("can_list_checks"), s.readCheckHistory)
	app.Add(read, "/automation/checks/"+pk+"/status/", s.authenticate, requireRead("can_list_automation_policies", "can_manage_automation_policies"), s.readPolicyCheckStatus)
}

func (s *Server) readChecks(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	query := checkReadQuery(db)
	detail := c.Params("pk") != ""
	if detail {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		query = query.Where("ch.id = ?", id)
	} else if strings.TrimLeft(c.Params("policy"), "0") != "" {
		var n int64
		if err := db.Table("automation_policy").Where("id::numeric = ?::numeric", c.Params("policy")).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return lookupError(gorm.ErrRecordNotFound, "Policy")
		}
		query = query.Where("ch.policy_id::numeric = ?::numeric", c.Params("policy"))
	} else {
		// Policy checks (agent=NULL) remain visible under every client/site scope.
		allowed := agentScope(db.Table("agents_agent a").Joins("JOIN clients_site s ON s.id=a.site_id"), c).Select("a.id")
		query = query.Where("ch.agent_id IS NULL OR ch.agent_id IN (?)", allowed)
	}
	var records []checkReadRecord
	if err := query.Select(checkReadSelect).Order("ch.id").Find(&records).Error; err != nil {
		return err
	}

	if detail && len(records) == 0 {
		return lookupError(gorm.ErrRecordNotFound, "Check")
	}
	if detail && records[0].AgentID != nil {
		if err := s.hasPermOnAgent(c, *records[0].AgentID); err != nil {
			return err
		}
	}
	out, err := serializeChecks(db, records)
	if err != nil {
		return err
	}
	if detail {
		return c.JSON(out[0])
	}
	return c.JSON(out)
}

type checkReadRecord struct {
	Payload    json.RawMessage
	AgentID    *string
	ScriptName *string
	Template   json.RawMessage
}

const checkReadSelect = `to_jsonb(ch) AS payload,a.agent_id,sc.name AS script_name,
 CASE WHEN t.id IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('name',t.name,'always_email',t.check_always_email,'always_text',t.check_always_text,'always_alert',t.check_always_alert) END AS template`

func checkReadQuery(db *gorm.DB) *gorm.DB {
	return db.Table("checks_check ch").Joins("LEFT JOIN agents_agent a ON a.id=ch.agent_id LEFT JOIN clients_site s ON s.id=a.site_id LEFT JOIN scripts_script sc ON sc.id=ch.script_id LEFT JOIN alerts_alerttemplate t ON t.id=a.alert_template_id")
}

func serializeChecks(db *gorm.DB, records []checkReadRecord) ([]map[string]any, error) {
	out := make([]map[string]any, len(records))
	ids := make([]any, len(records))
	for i, r := range records {
		row, err := decodeRow(r.Payload)
		if err != nil {
			return nil, err
		}
		desc, err := checkDescription(row, r.ScriptName)
		if err != nil {
			return nil, err
		}
		renameAlertFields(row, "agent", "policy", "script")
		row["readable_desc"], row["alert_template"], row["check_result"] = desc, r.Template, fiber.Map{}
		row["assignedtasks"] = []map[string]any{}
		out[i], ids[i] = row, row["id"]
	}
	if len(ids) > 0 {
		rows, err := db.Raw("SELECT to_jsonb(t) FROM autotasks_automatedtask t WHERE assigned_check_id IN ? ORDER BY id", ids).Rows()
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		byCheck := map[string][]map[string]any{}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return nil, err
			}
			task, err := decodeRow(raw)
			if err != nil {
				return nil, err
			}
			renameAlertFields(task, "agent", "policy", "custom_field", "assigned_check")
			for _, key := range []string{"run_time_date", "expire_date"} {
				if text, ok := task[key].(string); ok {
					t, err := time.Parse(time.RFC3339Nano, text)
					if err != nil {
						return nil, err
					}
					task[key] = datetime(&t)
				}
			}
			key := fmt.Sprint(task["assigned_check"])
			byCheck[key] = append(byCheck[key], task)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, row := range out {
			if tasks := byCheck[fmt.Sprint(row["id"])]; tasks != nil {
				row["assignedtasks"] = tasks
			}
		}
	}
	return out, nil
}

func checkDescription(row map[string]any, scriptName *string) (string, error) {
	nullable := func(v any) string {
		if v == nil {
			return "None"
		}
		return fmt.Sprint(v)
	}
	threshold := ""
	for _, key := range []string{"warning_threshold", "error_threshold"} {
		if value := row[key]; value != nil && fmt.Sprint(value) != "0" {
			label := " Warning Threshold: "
			if key == "error_threshold" {
				label = " Error Threshold: "
			}
			threshold += label + fmt.Sprint(value) + "%"
		}
	}
	switch row["check_type"] {
	case "diskspace":
		return "Disk Space Check: Drive " + nullable(row["disk"]) + " - " + threshold, nil
	case "cpuload":
		return "CPU Load Check - " + threshold, nil
	case "memory":
		return "Memory Check - " + threshold, nil
	case "ping":
		return "Ping Check: " + nullable(row["name"]), nil
	case "winsvc":
		return "Service Check: " + nullable(row["svc_display_name"]), nil
	case "eventlog":
		return "Event Log Check: " + nullable(row["name"]), nil
	case "script":
		if scriptName == nil {
			return "", errors.New("script check has no script")
		}
		return "Script Check: " + *scriptName, nil
	default:
		return "n/a", nil
	}
}

func (s *Server) readPolicyCheckStatus(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	rows, err := s.DB.WithContext(c.Context()).Raw("SELECT to_jsonb(r) || jsonb_build_object('hostname',a.hostname) FROM checks_checkresult r JOIN agents_agent a ON a.id=r.agent_id WHERE r.assigned_check_id = ? ORDER BY r.id", id).Rows()
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
		row, err := decodeCheckResult(raw)
		if err != nil {
			return err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(out)
}

func decodeCheckResult(raw []byte) (map[string]any, error) {
	row, err := decodeRow(raw)
	if err != nil {
		return nil, err
	}
	renameAlertFields(row, "agent", "assigned_check")
	if value, ok := row["last_run"].(string); ok {
		t, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, err
		}
		row["last_run"] = datetime(&t)
	}
	return row, nil
}

func (s *Server) readCheckHistory(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	var result []struct {
		CheckID int64
		AgentID string
	}
	db := s.DB.WithContext(c.Context())
	if err := db.Table("checks_checkresult r").Joins("JOIN agents_agent a ON a.id=r.agent_id").Select("r.assigned_check_id AS check_id,a.agent_id").Where("r.id = ?", id).Find(&result).Error; err != nil {
		return err
	}
	if len(result) == 0 {
		return lookupError(gorm.ErrRecordNotFound, "CheckResult")
	}
	if err := s.hasPermOnAgent(c, result[0].AgentID); err != nil {
		return err
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	query := db.Table("checks_checkhistory").Where("check_id = ? AND agent_id = ?", result[0].CheckID, result[0].AgentID)
	if raw, ok := input["timeFilter"]; ok {
		var days float64
		switch jsonType(raw) {
		case "bool":
			if string(raw) == "true" {
				days = 1
			}
		case "int", "float":
			if err := json.Unmarshal(raw, &days); err != nil {
				return err
			}
		default:
			return validationError{"timeFilter": {"A finite number of days is required."}}
		}
		if days != 0 {
			if math.IsNaN(days) || math.IsInf(days, 0) || math.Abs(days) > 999999999 {
				return validationError{"timeFilter": {"The date range is out of bounds."}}
			}
			now := time.Now().UTC()
			seconds := days * 86400
			// AddDate avoids time.Duration's much narrower ~292-year range.
			lower := now.AddDate(0, 0, -int(days)).Add(-time.Duration((seconds - math.Trunc(days)*86400) * float64(time.Second)))
			if lower.Year() < 1 || lower.Year() > 9999 {
				return validationError{"timeFilter": {"The date range is out of bounds."}}
			}
			query = query.Where("x <= ? AND x > ?", now, lower)
		}
	}
	var rows []struct {
		X       time.Time
		Y       *int64
		Results json.RawMessage
	}
	if err := query.Select("x,y,results").Order("x DESC").Find(&rows).Error; err != nil {
		return err
	}
	out := make([]fiber.Map, len(rows))
	for i, r := range rows {
		out[i] = fiber.Map{"x": datetime(&r.X), "y": r.Y, "results": r.Results}
	}
	return c.JSON(out)
}
