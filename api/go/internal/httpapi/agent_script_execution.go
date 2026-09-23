package httpapi

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerScriptExecution(app *fiber.App) {
	app.Add([]string{fiber.MethodPost, fiber.MethodGet, fiber.MethodHead, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete}, "/agents/:agent_id/runscript/", s.authenticate, require("can_run_scripts"), s.executeStoredScript)
}

type scriptExecutionInput struct {
	ScriptID, Timeout int64
	Args, Env         []string
	RunAsUser         bool
	Output            string
	CustomFieldID     int64
	SaveAllOutput     bool
}

func parseScriptExecution(input map[string]json.RawMessage) (scriptExecutionInput, error) {
	var out scriptExecutionInput
	var mode string
	if jsonType(input["output"]) != "str" || json.Unmarshal(input["output"], &mode) != nil {
		return out, validationError{"output": {"A string is required."}}
	}
	if mode != "wait" && mode != "forget" && mode != "note" && mode != "collector" && mode != "note_async" {
		return out, fiber.NewError(501, "Unsupported script output mode.")
	}
	out.Output = mode
	if mode == "collector" {
		kind := jsonType(input["custom_field"])
		if kind != "int" && kind != "str" {
			return out, validationError{"custom_field": {"A custom field ID is required."}}
		}
		var messages []string
		out.CustomFieldID, messages = relatedID(input["custom_field"])
		if len(messages) != 0 {
			return out, validationError{"custom_field": messages}
		}
		if jsonType(input["save_all_output"]) != "bool" || json.Unmarshal(input["save_all_output"], &out.SaveAllOutput) != nil {
			return out, validationError{"save_all_output": {"A boolean is required."}}
		}
	}
	if raw, present := input["run_on_server"]; present && jsonType(raw) != "NoneType" {
		var server bool
		if jsonType(raw) != "bool" || json.Unmarshal(raw, &server) != nil {
			return out, validationError{"run_on_server": {"A boolean is required."}}
		}
		if server {
			return out, fiber.NewError(501, "Server-side script execution is not supported.")
		}
	}
	if kind := jsonType(input["script"]); kind != "int" && kind != "str" {
		return out, validationError{"script": {"A script ID is required."}}
	}
	var messages []string
	out.ScriptID, messages = relatedID(input["script"])
	if len(messages) != 0 {
		return out, validationError{"script": messages}
	}
	for key, target := range map[string]*[]string{"args": &out.Args, "env_vars": &out.Env} {
		raw, present := input[key]
		if !present {
			return out, validationError{key: {"This field is required."}}
		}
		if jsonType(raw) == "NoneType" {
			*target = []string{}
			continue
		}
		if jsonType(raw) != "list" {
			return out, validationError{key: {"A list of strings is required."}}
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return out, err
		}
		*target = []string{}
		for _, entry := range entries {
			var text string
			if jsonType(entry) != "str" || json.Unmarshal(entry, &text) != nil {
				return out, validationError{key: {"A list of strings is required."}}
			}
			*target = append(*target, text)
		}
	}
	if jsonType(input["run_as_user"]) != "bool" || json.Unmarshal(input["run_as_user"], &out.RunAsUser) != nil {
		return out, validationError{"run_as_user": {"A boolean is required."}}
	}
	raw := input["timeout"]
	text := string(raw)
	if jsonType(raw) == "str" {
		if err := json.Unmarshal(raw, &text); err != nil {
			return out, err
		}
	} else if jsonType(raw) != "int" {
		return out, validationError{"timeout": {"An integer from 1 to 180 is required."}}
	}
	number, valid := registryPage(text)
	var err error
	if valid {
		out.Timeout, err = strconv.ParseInt(number.String(), 10, 64)
	}
	if !valid || err != nil || out.Timeout < 1 || out.Timeout > 180 {
		return out, validationError{"timeout": {"An integer from 1 to 180 is required."}}
	}
	return out, nil
}

func (s *Server) executeStoredScript(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	if c.Method() != fiber.MethodPost {
		return fiber.NewError(405, "Method \""+c.Method()+"\" not allowed.")
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	request, err := parseScriptExecution(input)
	if err != nil {
		return err
	}
	var payload map[string]any
	var successMessage string
	var collector scriptCollector
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		if request.Output == "note_async" {
			if err := requireScriptNoteCompletion(tx); err != nil {
				return err
			}
		}
		if request.Output == "collector" {
			var err error
			collector, err = loadScriptCollector(tx, pk, request.CustomFieldID, false)
			if err != nil {
				return err
			}
		}
		var script struct {
			ID                      int64
			Name, Shell, ScriptBody string
			RunAsUser               bool
		}
		if err := tx.Table("scripts_script").Select("id,name,shell,COALESCE(script_body,'') AS script_body,run_as_user").Where("id = ?", request.ScriptID).Take(&script).Error; err != nil {
			return lookupError(err, "Script")
		}
		lookup := newScriptValueResolver(tx, "agent", pk)
		var emptyLookups []string
		resolve := func(expression string) (any, error) {
			value, err := lookup(expression)
			if err == nil && value == nil {
				emptyLookups = append(emptyLookups, expression)
			}
			return value, err
		}
		args, err := expandScriptArgs(request.Args, script.Shell, resolve)
		if err != nil {
			return scriptExpansionFailure(err)
		}
		env, err := expandScriptEnv(request.Env, script.Shell, resolve)
		if err != nil {
			return scriptExpansionFailure(err)
		}
		code, err := expandScriptSnippets(script.ScriptBody, func(name string) (string, bool, error) {
			var snippet struct{ Code string }
			err := tx.Table("scripts_scriptsnippet").Select("code").Where("name = ?", name).Take(&snippet).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "", false, nil
			}
			return snippet.Code, err == nil, err
		})
		if err != nil {
			return scriptExpansionFailure(err)
		}
		if len(emptyLookups) > 0 {
			var settings struct{ AgentDebugLevel string }
			if err := tx.Table("core_coresettings").Select("agent_debug_level").Order("id").Take(&settings).Error; err != nil {
				return err
			}
			if settings.AgentDebugLevel == "info" || settings.AgentDebugLevel == "warning" || settings.AgentDebugLevel == "error" {
				for _, expression := range emptyLookups {
					message := "Couldn't lookup value for: " + expression + ". Make sure it exists"
					if err := tx.Exec("INSERT INTO logs_debuglog (entry_time,agent_id,log_level,log_type,message) VALUES (?,NULL,'error','scripting',?)", time.Now().UTC(), message).Error; err != nil {
						return err
					}
				}
			}
		}
		var hostname string
		if err := tx.Table("agents_agent").Select("hostname").Where("id = ?", pk).Scan(&hostname).Error; err != nil {
			return err
		}
		username := principal(c).User.Username
		successMessage = script.Name + " will now be run on " + hostname
		if err := audit.Write(tx, audit.Entry{Username: username, Agent: &hostname, AgentID: &id, Action: "execute_script", ObjectType: "agent",
			Message: username + " ran script: \"" + script.Name + "\" on " + hostname, DebugInfo: map[string]any{"ip": c.IP()}}); err != nil {
			return err
		}
		shortUser := []rune(username)
		if len(shortUser) > 50 {
			shortUser = shortUser[:50]
		}
		var historyID int64
		err = tx.Raw("INSERT INTO agents_agenthistory (agent_id,time,type,command,username,script_id,collector_all_output,save_to_agent_note) VALUES (?, ?, 'script_run', '', ?, ?, false, ?) RETURNING id", pk, time.Now().UTC(), string(shortUser), script.ID, request.Output == "note_async").Scan(&historyID).Error
		if err != nil {
			return err
		}
		if request.Output == "note_async" {
			if err := tx.Exec("INSERT INTO go_script_note_completion (history_id,agent_id) VALUES (?,?)", historyID, pk).Error; err != nil {
				return err
			}
		}
		payload = map[string]any{"func": "runscript", "timeout": request.Timeout + 3, "script_args": args, "payload": map[string]any{"code": code, "shell": script.Shell}, "id": historyID,
			"run_as_user": request.RunAsUser || script.RunAsUser, "env_vars": env, "nushell_enable_config": s.NushellEnableConfig, "deno_default_permissions": s.DenoDefaultPermissions}
		return nil
	})
	if err != nil {
		return err
	}
	// History and audit are committed before callbacks can arrive; no DB
	// transaction remains open and ambiguous commands are never resent.
	if request.Output == "forget" || request.Output == "note_async" {
		err := s.NATS.Publish(c.Context(), id, payload, 10*time.Second)
		status, message := scriptPublishResponse(err, successMessage)
		return c.Status(status).JSON(message)
	}
	reply, requestErr := s.NATS.Request(c.Context(), id, payload, time.Duration(request.Timeout+3)*time.Second)
	status, body, err := serviceReadResponse(reply, requestErr, false)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return fiber.NewError(502, "Invalid agent reply.")
	}
	if request.Output == "note" && status == 200 {
		note, err := scriptNoteValue(body)
		if err != nil {
			return err
		}
		// Note is a plain Django model without audit or background hooks.
		// A failure here cannot undo remote execution; never dispatch again.
		if err := s.DB.WithContext(c.Context()).Table("agents_note").Create(map[string]any{
			"agent_id": pk, "user_id": principal(c).User.ID,
			"note": note, "entry_time": time.Now().UTC(),
		}).Error; err != nil {
			return err
		}
	}
	if request.Output == "collector" && status == 200 {
		value, err := scriptCollectorValue(body, request.SaveAllOutput)
		if err != nil {
			return err
		}
		if err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
			return saveScriptCollector(tx, pk, collector, value)
		}); err != nil {
			return err
		}
	}
	return c.Status(status).Type("json").Send(encoded)
}

func scriptNoteValue(reply any) (any, error) {
	if reply == nil {
		return nil, nil
	}
	text, ok := reply.(string)
	if !ok {
		// Script output is text. Do not turn malformed structured replies into
		// notes using a representation different from Python's TextField.
		return nil, fiber.NewError(502, "Invalid agent reply for script note.")
	}
	if strings.ContainsRune(text, 0) {
		return nil, fiber.NewError(502, "Invalid agent reply for script note.")
	}
	return text, nil
}

func scriptPublishResponse(err error, success string) (int, string) {
	if err == nil {
		return 200, success
	}
	var failure *agentbus.PublishError
	if errors.As(err, &failure) && failure.Ambiguous {
		return 502, "The script request may have been sent; delivery could not be confirmed."
	}
	return 503, "Unable to publish the script execution request."
}

func scriptExpansionFailure(err error) error {
	if errors.Is(err, ErrUnsupportedScriptExpansion) || errors.Is(err, ErrScriptValueMissing) || errors.Is(err, ErrScriptValueAmbiguous) {
		return validationError{"templates": {"Script template lookup or syntax is unsupported, missing, or ambiguous."}}
	}
	return err
}
