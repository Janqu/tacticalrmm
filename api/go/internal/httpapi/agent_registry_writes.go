package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerRegistryWrites(app *fiber.App) {
	for _, action := range []string{"create-key", "delete-key", "rename-key", "create-value", "delete-value", "rename-value", "modify-value"} {
		app.Add([]string{fiber.MethodGet, fiber.MethodHead, fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete}, "/agents/:agent_id/registry/"+action+"/", s.authenticate, require("can_use_registry"), s.writeAgentRegistry)
	}
}

func (s *Server) writeAgentRegistry(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	parts := strings.Split(strings.Trim(c.Route().Path, "/"), "/")
	action := parts[len(parts)-1]
	method := fiber.MethodPost
	if strings.HasPrefix(action, "delete-") {
		method = fiber.MethodDelete
	}
	if c.Method() != method {
		return fiber.NewError(405, "Method \""+c.Method()+"\" not allowed.")
	}
	if _, err := s.agentPK(c, id); err != nil {
		return err
	}
	var version string
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("version").Where("agent_id = ?", id).Scan(&version).Error; err != nil {
		return err
	}
	supported, valid := registryVersionSupported(version)
	if !valid {
		return c.Status(400).JSON("Invalid agent version.")
	}
	if !supported {
		return c.Status(400).JSON("This feature requires agent version 2.10.0 or higher.")
	}
	input := map[string]json.RawMessage{}
	if c.Method() == fiber.MethodDelete {
		for _, key := range []string{"path", "name"} {
			value, _ := lastQuery(c, key)
			input[key], _ = json.Marshal(value)
		}
	} else {
		input, err = jsonObject(c)
		if err != nil {
			return err
		}
	}
	payload, failure, err := registryWritePayload(action, input)
	if err != nil {
		return err
	}
	if failure != "" {
		return c.Status(400).JSON(failure)
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	timeout := 30 * time.Second
	if action == "rename-key" {
		timeout = 60 * time.Second
	}
	command := "registry_" + strings.ReplaceAll(action, "-", "_")
	reply, err := s.NATS.Request(c.Context(), id, map[string]any{"func": command, "payload": payload}, timeout)
	status, body := registryWriteResponse(action, payload, reply, err)
	return c.Status(status).JSON(body)
}

func registryWritePayload(action string, input map[string]json.RawMessage) (map[string]any, string, error) {
	keys := []string{"path"}
	switch action {
	case "rename-key":
		keys = []string{"old_path", "new_path"}
	case "create-value":
		keys = []string{"path", "type", "name"}
	case "modify-value":
		keys = []string{"path", "name", "type"}
	case "delete-value":
		keys = []string{"path", "name"}
	case "rename-value":
		keys = []string{"path", "old_name", "new_name"}
	}
	payload := map[string]any{}
	for _, key := range keys {
		var value any
		if raw := input[key]; len(raw) != 0 {
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, "", err
			}
		}
		text := ""
		if pyTruthy(value) {
			var ok bool
			text, ok = value.(string)
			if !ok {
				return nil, "", validationError{key: {"A string is required."}}
			}
		}
		if strings.HasSuffix(key, "path") || key == "type" {
			text = strings.TrimSpace(text)
		}
		if key == "type" {
			text = strings.ToUpper(text)
		}
		payload[key] = text
		if text == "" {
			message := map[string]string{"path": "Registry path is required", "type": "Registry value type is required", "name": "Registry value name is required", "old_name": "Old value name is required", "new_name": "New value name is required", "old_path": "Both 'old_path' and 'new_path' are required", "new_path": "Both 'old_path' and 'new_path' are required"}[key]
			return nil, message, nil
		}
	}
	if action == "rename-key" && payload["old_path"] == payload["new_path"] {
		return nil, "Old and new path cannot be the same", nil
	}
	if action == "rename-value" && payload["old_name"] == payload["new_name"] {
		return nil, "Old and new value names cannot be the same", nil
	}
	if action == "create-value" || action == "modify-value" {
		var value any
		if raw := input["data"]; len(raw) != 0 {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				return nil, "", err
			}
		}
		data, err := registryWireData(value)
		if err != nil {
			return nil, "", validationError{"data": {"Numbers must be representable by MessagePack."}}
		}
		payload["data"] = data
	}
	return payload, "", nil
}

func registryWireData(value any) (any, error) {
	switch value := value.(type) {
	case json.Number:
		text := value.String()
		if !strings.ContainsAny(text, ".eE") {
			if number, err := strconv.ParseInt(text, 10, 64); err == nil {
				return number, nil
			}
			return strconv.ParseUint(text, 10, 64)
		}
		number, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
			return nil, errors.New("unrepresentable registry number")
		}
		return number, nil
	case []any:
		for i, item := range value {
			item, err := registryWireData(item)
			if err != nil {
				return nil, err
			}
			value[i] = item
		}
		return value, nil
	case map[string]any:
		for key, item := range value {
			item, err := registryWireData(item)
			if err != nil {
				return nil, err
			}
			value[key] = item
		}
		return value, nil
	default:
		return value, nil
	}
}

func registryWriteResponse(action string, payload map[string]any, reply any, err error) (int, any) {
	invalid := fiber.Map{"detail": "Invalid response from the agent."}
	if errors.Is(err, agentbus.ErrTimeout) || errors.Is(err, agentbus.ErrUnavailable) {
		return 400, "Unable to contact the agent"
	}
	if err != nil {
		return 502, invalid
	}
	data, ok := reply.(map[string]any)
	if text, isString := reply.(string); isString {
		if text == "timeout" || text == "natsdown" {
			return 400, "Unable to contact the agent"
		}
		if text == "ok" && (action == "create-key" || action == "delete-key" || action == "rename-key" || action == "delete-value") {
			data, ok = map[string]any{}, true
		}
	}
	if !ok {
		return 502, invalid
	}
	if failure, exists := data["error"]; exists {
		switch failure.(type) {
		case []any, map[string]any:
			return 502, invalid
		}
		label := "Registry"
		for _, word := range strings.Split(action, "-") {
			label += " " + strings.ToUpper(word[:1]) + word[1:]
		}
		return 400, label + " failed: " + pyStr(failure)
	}
	value := func(key string) any {
		if result, exists := data[key]; exists {
			return result
		}
		return payload[key]
	}
	out := map[string]any{"status": "success"}
	switch action {
	case "create-key":
		out["path"] = payload["path"]
	case "delete-key":
		out["deleted_path"] = payload["path"]
	case "rename-key":
		out["old_path"], out["new_path"] = payload["old_path"], payload["new_path"]
	case "delete-value":
		out["name"] = payload["name"]
	case "rename-value":
		out["old_name"], out["new_name"] = payload["old_name"], value("new_name")
	default:
		out["data"] = map[string]any{"name": value("name"), "type": value("type"), "data": value("data")}
	}
	if _, err := json.Marshal(out); err != nil {
		return 502, invalid
	}
	return 200, out
}
