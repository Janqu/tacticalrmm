package httpapi

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerRawCommands(app *fiber.App) {
	app.Add([]string{fiber.MethodPost, fiber.MethodGet, fiber.MethodHead, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete}, "/agents/:agent_id/cmd/", s.authenticate, require("can_send_cmd"), s.sendAgentRawCommand)
}

func (s *Server) sendAgentRawCommand(c fiber.Ctx) error {
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
	var hostname string
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("hostname").Where("id = ?", pk).Scan(&hostname).Error; err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	command, err := parseRawCommand(input)
	if err != nil {
		return err
	}
	username := principal(c).User.Username
	shortUser := []rune(username)
	if len(shortUser) > 50 {
		shortUser = shortUser[:50]
	}
	var historyID int64
	// Commit before contacting the agent: its result callback may arrive first.
	err = s.DB.WithContext(c.Context()).Raw("INSERT INTO agents_agenthistory (agent_id,time,type,command,username,collector_all_output,save_to_agent_note) VALUES (?, ?, 'cmd_run', ?, ?, false, false) RETURNING id", pk, time.Now().UTC(), command.Command, string(shortUser)).Scan(&historyID).Error
	if err != nil {
		return err
	}
	payload := map[string]any{"func": "rawcmd", "timeout": command.Timeout, "payload": map[string]any{"command": command.Command, "shell": command.Shell}, "run_as_user": command.RunAsUser, "id": historyID}
	// Ambiguous failures retain history. Never retry a command automatically.
	reply, requestErr := s.NATS.Request(c.Context(), id, payload, time.Duration(command.Timeout+2)*time.Second)
	status, reply, err := serviceReadResponse(reply, requestErr, false)
	if err != nil {
		return err
	}
	if status != 200 {
		return c.Status(status).JSON(reply)
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		return fiber.NewError(502, "Invalid agent reply.")
	}
	// The command may already have run if this audit insert fails. Keep history
	// and return the failure; neither the remote command nor audit is retried.
	err = audit.Write(s.DB.WithContext(c.Context()), audit.Entry{Username: username, Agent: &hostname, AgentID: &id,
		Action: "execute_command", ObjectType: "agent", AfterValue: command.Command,
		Message: username + " issued " + command.Shell + " command on " + hostname + ".", DebugInfo: map[string]any{"ip": c.IP()}})
	if err != nil {
		return err
	}
	return c.Type("json").Send(encoded)
}

type rawCommand struct {
	Command, Shell string
	Timeout        int64
	RunAsUser      bool
}

func parseRawCommand(input map[string]json.RawMessage) (rawCommand, error) {
	var command rawCommand
	readString := func(key string) (string, error) {
		var value string
		if jsonType(input[key]) != "str" || json.Unmarshal(input[key], &value) != nil {
			return "", validationError{key: {"A string is required."}}
		}
		return value, nil
	}
	var err error
	command.Command, err = readString("cmd")
	if err != nil {
		return command, err
	}
	command.Shell, err = readString("shell")
	if err != nil {
		return command, err
	}
	if strings.TrimSpace(command.Shell) == "" {
		return command, validationError{"shell": {"A non-empty shell is required."}}
	}
	if command.Shell == "custom" {
		custom, err := readString("custom_shell")
		if err != nil {
			return command, err
		}
		if custom != "" {
			command.Shell = custom
		}
	}
	if jsonType(input["run_as_user"]) != "bool" || json.Unmarshal(input["run_as_user"], &command.RunAsUser) != nil {
		return command, validationError{"run_as_user": {"A boolean is required."}}
	}
	raw := input["timeout"]
	text := string(raw)
	if jsonType(raw) == "str" {
		if err := json.Unmarshal(raw, &text); err != nil {
			return command, err
		}
	} else if jsonType(raw) != "int" {
		return command, validationError{"timeout": {"An integer from 1 to 180 is required."}}
	}
	normalized, ok := registryPage(text)
	if ok {
		command.Timeout, err = strconv.ParseInt(normalized.String(), 10, 64)
	}
	if !ok || err != nil || command.Timeout < 1 || command.Timeout > 180 {
		return command, validationError{"timeout": {"An integer from 1 to 180 is required."}}
	}
	return command, nil
}
