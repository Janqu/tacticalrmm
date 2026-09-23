package httpapi

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerAutoTaskReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	permission := requireRead("can_list_autotasks", "can_manage_autotasks")
	app.Add(read, "/tasks/", s.authenticate, permission, s.readAutoTasks(false, false))
	app.Add(read, "/tasks/:pk<regex(^[0-9]+$)>/", s.authenticate, permission, s.readAutoTasks(false, true))
	app.Add(read, "/automation/policies/:pk<regex(^[0-9]+$)>/tasks/", s.authenticate, permission, s.readAutoTasks(true, false))
	for _, suffix := range []string{"status/", "run/"} {
		app.Add(read, "/automation/tasks/:pk<regex(^[0-9]+$)>/"+suffix, s.authenticate, automationReadPermission, s.readAutoTaskStatus)
	}
}

func taskDateFields(row map[string]any, fields ...string) error {
	for _, field := range fields {
		if row[field] == nil {
			continue
		}
		value, ok := row[field].(string)
		if !ok {
			return fmt.Errorf("invalid task date %s", field)
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return err
		}
		row[field] = *datetime(&parsed)
	}
	return nil
}

func (s *Server) readAutoTasks(policy, detail bool) fiber.Handler {
	return func(c fiber.Ctx) error {
		db := s.DB.WithContext(c.Context())
		query := db.Table("autotasks_automatedtask t").Joins("LEFT JOIN agents_agent a ON a.id=t.agent_id").Joins("LEFT JOIN clients_site s ON s.id=a.site_id")
		var id int64
		if policy || detail {
			var err error
			id, err = identifier(c)
			if err != nil {
				return err
			}
		}
		if detail {
			query = query.Where("t.id = ?", id)
		} else if policy && id != 0 {
			var count int64
			if err := db.Table("automation_policy").Where("id = ?", id).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return lookupError(gorm.ErrRecordNotFound, "Policy")
			}
			query = query.Where("t.policy_id = ?", id)
		} else {
			// Policy/unassigned tasks remain visible to scoped users, as in PermissionQuerySet.
			allowed := agentScope(db.Table("agents_agent a").Joins("JOIN clients_site s ON s.id=a.site_id"), c).Select("a.id")
			query = query.Where("t.agent_id IS NULL OR t.agent_id IN (?)", allowed)
		}
		rows, err := query.Select("to_jsonb(t), a.agent_id").Order("t.id").Rows()
		if err != nil {
			return err
		}
		type taskRow struct {
			value map[string]any
			agent *string
		}
		fetched := []taskRow{}
		for rows.Next() {
			var raw []byte
			var agent *string
			if err := rows.Scan(&raw, &agent); err != nil {
				rows.Close()
				return err
			}
			value, err := decodeRow(raw)
			if err != nil {
				rows.Close()
				return err
			}
			fetched = append(fetched, taskRow{value, agent})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if detail && len(fetched) == 0 {
			return lookupError(gorm.ErrRecordNotFound, "AutomatedTask")
		}
		out := make([]map[string]any, 0, len(fetched))
		for _, entry := range fetched {
			row := entry.value
			if detail && entry.agent != nil {
				if err := s.hasPermOnAgent(c, *entry.agent); err != nil {
					return err
				}
			}
			if err := serializeAutoTask(db, row); err != nil {
				return err
			}
			out = append(out, row)
		}
		if detail {
			return c.JSON(out[0])
		}
		return c.JSON(out)
	}
}

// serializeAutoTask is the TaskSerializer projection shared by library and agent reads.
func serializeAutoTask(db *gorm.DB, row map[string]any) error {
	schedule, err := autoTaskSchedule(row)
	if err != nil {
		return err
	}
	row["schedule"] = schedule
	if err := taskDateFields(row, "run_time_date", "expire_date"); err != nil {
		return err
	}
	row["task_result"] = map[string]any{}
	row["alert_template"] = nil
	if row["agent_id"] != nil {
		templates, err := db.Raw("SELECT jsonb_build_object('name',x.name,'always_email',x.task_always_email,'always_text',x.task_always_text,'always_alert',x.task_always_alert) FROM alerts_alerttemplate x JOIN agents_agent a ON a.alert_template_id=x.id WHERE a.id = ?", row["agent_id"]).Rows()
		if err != nil {
			return err
		}
		if templates.Next() {
			var raw json.RawMessage
			if err := templates.Scan(&raw); err != nil {
				templates.Close()
				return err
			}
			row["alert_template"] = raw
		}
		err = templates.Err()
		templates.Close()
		if err != nil {
			return err
		}
	}
	if row["assigned_check_id"] != nil {
		// ReadOnlyField omits check_name when the source relation is absent.
		var raw []byte
		if err := db.Raw("SELECT to_jsonb(ch) || jsonb_build_object('script_name',sc.name) FROM checks_check ch LEFT JOIN scripts_script sc ON sc.id=ch.script_id WHERE ch.id = ?", row["assigned_check_id"]).Row().Scan(&raw); err != nil {
			return err
		}
		check, err := decodeRow(raw)
		if err != nil {
			return err
		}
		var scriptName *string
		if name, ok := check["script_name"].(string); ok {
			scriptName = &name
		}
		name, err := checkDescription(check, scriptName)
		if err != nil {
			return err
		}
		row["check_name"] = name
	}
	renameAlertFields(row, "agent", "policy", "custom_field", "assigned_check")
	return nil
}

func (s *Server) readAutoTaskStatus(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	// Django checks the automation permission but does not apply agent role scope.
	rows, err := s.DB.WithContext(c.Context()).Raw("SELECT to_jsonb(r) || jsonb_build_object('hostname',a.hostname) FROM autotasks_taskresult r JOIN agents_agent a ON a.id=r.agent_id WHERE r.task_id = ? ORDER BY r.id", id).Rows()
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
		if err := serializeTaskResult(row); err != nil {
			return err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(out)
}

func taskBits(row map[string]any, key string, names []string, all int64, allName string) (string, error) {
	n, ok := row[key].(json.Number)
	if !ok {
		return "", fmt.Errorf("missing task bitmask %s", key)
	}
	bits, err := n.Int64()
	if err != nil {
		return "", err
	}
	if bits == all {
		return allName, nil
	}
	out := []string{}
	for i, name := range names {
		if bits&(int64(1)<<i) != 0 {
			out = append(out, name)
		}
	}
	return strings.Join(out, ", "), nil
}

func autoTaskSchedule(row map[string]any) (any, error) {
	kind, _ := row["task_type"].(string)
	switch kind {
	case "manual":
		return "Manual", nil
	case "checkfailure":
		return "Every time check fails", nil
	case "onboarding":
		return "Onboarding: Runs once on task creation.", nil
	case "runonce", "daily", "weekly", "monthly", "monthlydow":
	default:
		return nil, nil
	}
	raw, _ := row["run_time_date"].(string)
	date, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil, err
	}
	date = date.UTC()
	clock := date.Format("03:04PM")
	value := func(key string) string {
		if row[key] == nil {
			return "None"
		}
		return fmt.Sprint(row[key])
	}
	if kind == "runonce" {
		return "Run once on " + date.Format("01/02/2006 03:04PM"), nil
	}
	if kind == "daily" {
		if value("daily_interval") == "1" {
			return "Daily at " + clock, nil
		}
		return "Every " + value("daily_interval") + " days at " + clock, nil
	}
	days := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	if kind == "weekly" {
		text, err := taskBits(row, "run_time_bit_weekdays", days, 127, "Every day")
		if err != nil {
			return nil, err
		}
		text += " at " + clock
		if value("weekly_interval") == "1" {
			text += " every 1 weeks"
		}
		return text, nil
	}
	months, err := taskBits(row, "monthly_months_of_year", []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}, 4095, "Every month")
	if err != nil {
		return nil, err
	}
	if kind == "monthly" {
		names := make([]string, 32)
		for i := 0; i < 31; i++ {
			names[i] = strconv.Itoa(i + 1)
		}
		names[31] = "Last Day"
		bits := value("monthly_days_of_month")
		text := ""
		switch bits {
		case "2147483648":
			text = "Last day"
		case "2147483647", "4294967295":
			text = "Every day"
		default:
			text, err = taskBits(row, "monthly_days_of_month", names, -1, "")
		}
		if err != nil {
			return nil, err
		}
		return "Runs on " + months + " on days " + text + " at " + clock, nil
	}
	weeks, err := taskBits(row, "monthly_weeks_of_month", []string{"First Week", "Second Week", "Third Week", "Fourth Week", "Last Week"}, 31, "Every week")
	if err != nil {
		return nil, err
	}
	weekdays, err := taskBits(row, "run_time_bit_weekdays", days, 127, "Every day")
	if err != nil {
		return nil, err
	}
	return "Runs on " + months + " on " + weeks + " on " + weekdays + " at " + clock, nil
}
