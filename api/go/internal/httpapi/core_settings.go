package httpapi

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/amidaware/tacticalrmm/api/go/internal/mesh"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

const coreSettingsTable = "core_coresettings"

// Secrets are masked in responses (tokens) and redacted in audit entries (all).
var (
	maskedTokenFields = []string{"open_ai_token", "minimax_token"}
	coreSecretFields  = []string{"open_ai_token", "minimax_token", "twilio_auth_token", "twilio_account_sid", "smtp_host_password", "mesh_token"}
	coreArrayColumns  = map[string]bool{"email_alert_recipients": true, "sms_alert_recipients": true}
)

func maskToken(value any) any {
	text, ok := value.(string)
	if !ok || text == "" {
		return value
	}
	n := utf8.RuneCountInString(text)
	if n <= 4 {
		return strings.Repeat("•", n)
	}
	runes := []rune(text)
	return strings.Repeat("•", n-4) + string(runes[n-4:])
}

var coreForeignKeys = []string{"workstation_policy", "server_policy", "alert_template"}

// readCore names foreign keys as DRF does (no _id suffix).
func readCore(tx *gorm.DB, lock bool) (map[string]any, error) {
	row, err := readRow(tx, coreSettingsTable, 0, lock)
	if err != nil {
		return nil, err
	}
	for _, field := range coreForeignKeys {
		row[field] = row[field+"_id"]
		delete(row, field+"_id")
	}
	return row, nil
}

func (s *Server) getCoreSettings(c fiber.Ctx) error {
	row, err := readCore(s.DB.WithContext(c.Context()), false)
	if err != nil {
		return err
	}
	for _, field := range maskedTokenFields {
		row[field] = maskToken(row[field])
	}
	row["all_timezones"] = allTimezones
	return c.JSON(row)
}

func relatedSpec(tx *gorm.DB, table string) parser {
	return func(raw json.RawMessage) (any, any) {
		if jsonType(raw) == "NoneType" {
			return nil, nil
		}
		id, messages := relatedID(raw)
		if len(messages) > 0 {
			return nil, messages
		}
		var count int64
		if err := tx.Table(table).Where("id = ?", id).Count(&count).Error; err != nil || count == 0 {
			return nil, []string{fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", id)}
		}
		return id, nil
	}
}

func signedIntSpec(raw json.RawMessage) (any, any) {
	value, problem := posIntSpec(raw)
	if problem == nil {
		return value, nil
	}
	kind := jsonType(raw)
	text := string(raw)
	if kind == "str" {
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, problem
		}
	}
	text = strings.TrimSpace(text)
	if (kind != "str" && kind != "int" && kind != "float") || !strings.HasPrefix(text, "-") {
		return nil, problem
	}
	magnitude := strings.TrimPrefix(text, "-")
	positive := json.RawMessage(magnitude)
	if kind == "str" {
		positive, _ = json.Marshal(magnitude)
	}
	n, messages := positiveIntegerField(positive)
	if len(messages) == 0 {
		return -n, nil
	}
	if len(messages) == 1 && messages[0] == "Ensure this value is less than or equal to 2147483647." {
		if boundary, err := strconv.ParseFloat(magnitude, 64); err == nil && boundary == 2147483648 {
			return int64(-2147483648), nil
		}
		return nil, []string{"Ensure this value is greater than or equal to -2147483648."}
	}
	return nil, messages
}

func listSpec(email bool) parser {
	return func(raw json.RawMessage) (any, any) {
		kind := jsonType(raw)
		if kind == "NoneType" {
			return nil, []string{"This field may not be null."}
		}
		var items []json.RawMessage
		if kind != "list" || json.Unmarshal(raw, &items) != nil {
			return nil, []string{fmt.Sprintf("Expected a list of items but got type \"%s\".", kind)}
		}
		max := 255
		if email {
			max = 254
		}
		values, problems := make([]any, 0, len(items)), map[string][]string{}
		for i, item := range items {
			value, messages := charField(item, max, true, true)
			if len(messages) == 0 && email && value != nil && !validEmail(*value) {
				messages = []string{"Enter a valid email address."}
			}
			if len(messages) > 0 {
				problems[fmt.Sprint(i)] = messages
			} else if value == nil {
				values = append(values, nil)
			} else {
				values = append(values, *value)
			}
		}
		if len(problems) > 0 {
			return nil, problems
		}
		return values, nil
	}
}

func coreParsers(tx *gorm.DB) map[string]parser {
	nullChar := charSpec(255, true, true)
	blankChar := charSpec(255, false, true)
	shell := func(choices ...string) parser { return choiceSpec(choices...) }
	return map[string]parser{
		"created_by": charSpec(255, true, true), "modified_by": charSpec(255, true, true),
		"email_alert_recipients": listSpec(true), "sms_alert_recipients": listSpec(false),
		"twilio_number": nullChar, "twilio_account_sid": nullChar, "twilio_auth_token": nullChar,
		"smtp_from_email": blankChar, "smtp_from_name": nullChar, "smtp_host": blankChar,
		"smtp_host_user": blankChar, "smtp_host_password": blankChar,
		"smtp_port": posIntSpec, "smtp_requires_auth": boolSpec,
		"default_time_zone":        choiceSpec(allTimezones...),
		"check_history_prune_days": posIntSpec, "resolved_alerts_prune_days": posIntSpec,
		"agent_history_prune_days": posIntSpec, "debug_log_prune_days": posIntSpec,
		"audit_log_prune_days": posIntSpec, "report_history_prune_days": posIntSpec,
		"agent_debug_level": choiceSpec("info", "warning", "error", "critical"),
		"clear_faults_days": signedIntSpec,
		"mesh_token":        nullChar, "mesh_username": nullChar, "mesh_site": nullChar,
		"mesh_device_group": nullChar, "mesh_company_name": nullChar,
		"sync_mesh_with_trmm": boolSpec, "agent_auto_update": boolSpec,
		"workstation_policy": relatedSpec(tx, "automation_policy"), "server_policy": relatedSpec(tx, "automation_policy"),
		"alert_template": relatedSpec(tx, "alerts_alerttemplate"),
		"date_format":    charSpec(30, false, true),
		"open_ai_token":  nullChar, "open_ai_model": blankChar,
		"ai_provider":   choiceSpec("openai", "minimax"),
		"minimax_token": nullChar, "minimax_model": blankChar,
		"enable_server_scripts": boolSpec, "enable_server_webterminal": boolSpec, "ai_chat_enabled": boolSpec,
		"notify_on_info_alerts": boolSpec, "notify_on_warning_alerts": boolSpec,
		"block_local_user_logon": boolSpec, "sso_enabled": boolSpec,
		"default_shell_windows": shell("cmd", "powershell", "custom"), "default_shell_windows_custom": charSpec(512, false, true),
		"default_shell_linux": shell("bash", "custom"), "default_shell_linux_custom": charSpec(512, false, true),
		"default_shell_darwin": shell("bash", "custom"), "default_shell_darwin_custom": charSpec(512, false, true),
		"terminal_mode": choiceSpec("new", "legacy"),
	}
}

func (s *Server) updateCoreSettings(c fiber.Ctx) error {
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := readCore(tx, true)
		if err != nil {
			return err
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		values, err := parseFields(input, coreParsers(tx))
		if err != nil {
			return err
		}
		// The shown token is masked; an unchanged masked value keeps the stored one.
		for _, field := range maskedTokenFields {
			if text, ok := values[field].(string); ok && strings.Contains(text, "•") {
				values[field] = before[field]
			}
		}
		after := map[string]any{}
		for key, value := range before {
			after[key] = value
		}
		for key, value := range values {
			after[key] = value
		}
		problems := nestedValidation{}
		for _, shell := range []string{"windows", "linux", "darwin"} {
			custom, _ := after["default_shell_"+shell+"_custom"].(string)
			if after["default_shell_"+shell] == "custom" && strings.TrimSpace(custom) == "" {
				problems["default_shell_"+shell+"_custom"] = []string{"Custom shell path is required."}
			}
		}
		if len(problems) > 0 {
			return problems
		}
		// Fail safe so local logons cannot be locked out.
		if after["sso_enabled"] != true && after["block_local_user_logon"] == true {
			after["block_local_user_logon"] = false
		}
		// ponytail: these side effects need Django-side services (code-sign
		// server call; Celery re-cache + Django Redis cache purge) that Go
		// does not own. Refuse rather than commit half of the behavior.
		if after["sso_enabled"] == true && before["sso_enabled"] != true {
			return fiber.NewError(501, "Enabling SSO requires code-sign token validation, which is not ported to the Go API.")
		}
		for _, field := range coreForeignKeys {
			if fmt.Sprint(before[field]) != fmt.Sprint(after[field]) {
				return fiber.NewError(501, "Changing default policies or alert template requires agent cache refresh, which is not ported to the Go API.")
			}
		}
		actor := principal(c).User.Username
		if !sameJSON(before, after) {
			if err := coreAudit(tx, c, "GetEditCoreSettings", "modify", "coresettings", "Global Site Settings", nil, before, after, coreSecretFields); err != nil {
				return err
			}
		}
		createdBy := after["created_by"]
		if text, _ := createdBy.(string); text == "" {
			createdBy = actor
		}
		set := map[string]any{"created_by": createdBy, "modified_by": actor, "modified_time": time.Now().UTC()}
		for key, value := range values {
			if key == "created_by" || key == "modified_by" {
				continue
			}
			set[key] = value
		}
		set["block_local_user_logon"] = after["block_local_user_logon"]
		columns := map[string]any{}
		for key, value := range set {
			switch {
			case key == "workstation_policy" || key == "server_policy" || key == "alert_template":
				columns[key+"_id"] = value
			case coreArrayColumns[key]:
				encoded, err := json.Marshal(value)
				if err != nil {
					return err
				}
				columns[key] = gorm.Expr("ARRAY(SELECT jsonb_array_elements_text(?::jsonb))", string(encoded))
			default:
				columns[key] = value
			}
		}
		set = columns
		if err := tx.Table(coreSettingsTable).Where("id = ?", before["id"]).Updates(set).Error; err != nil {
			return err
		}
		return mesh.Enqueue(tx)
	})
	if err != nil {
		return coreError(c, err)
	}
	return c.JSON("ok")
}

// sameJSON compares projections independent of Go numeric representation.
func sameJSON(a, b map[string]any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

// Django's permission classes treat HEAD like a non-GET method (the edit
// permission), which requireRead reproduces.
func (s *Server) coreRoutes(app *fiber.App) {
	rm := []string{fiber.MethodGet, fiber.MethodHead}
	app.Add(rm, "/core/settings/", s.authenticate, requireRead("can_view_core_settings", "can_edit_core_settings"), s.getCoreSettings)
	app.Put("/core/settings/", s.authenticate, require("can_edit_core_settings"), s.updateCoreSettings)
	// URLActionPerms: GET (and PATCH) need can_run_urlactions, others the core-settings edit permission.
	app.Add(rm, "/core/urlaction/", s.authenticate, requireRead("can_run_urlactions", "can_edit_core_settings"), urlActionModel.list(s))
	app.Post("/core/urlaction/", s.authenticate, require("can_edit_core_settings"), urlActionModel.create(s))
	app.Put("/core/urlaction/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_edit_core_settings"), urlActionModel.update(s))
	app.Delete("/core/urlaction/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_edit_core_settings"), urlActionModel.remove(s))
	app.Add(rm, "/core/keystore/", s.authenticate, requireRead("can_view_global_keystore", "can_edit_global_keystore"), keyStoreModel.list(s))
	app.Post("/core/keystore/", s.authenticate, require("can_edit_global_keystore"), keyStoreModel.create(s))
	app.Put("/core/keystore/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_edit_global_keystore"), keyStoreModel.update(s))
	app.Delete("/core/keystore/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_edit_global_keystore"), keyStoreModel.remove(s))
	app.Add(rm, "/core/codesign/", s.authenticate, require("can_code_sign"), s.getCodeSign)
	app.Delete("/core/codesign/", s.authenticate, require("can_code_sign"), s.deleteCodeSign)
}
