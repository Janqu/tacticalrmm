package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerServiceWrites(app *fiber.App) {
	app.Add([]string{fiber.MethodPost, fiber.MethodPut}, "/services/:agent_id/:svcname/", s.authenticate, require("can_manage_winsvcs"), s.writeAgentService)
}

func (s *Server) writeAgentService(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return err
	}
	name, err := serviceName(c)
	if err != nil {
		return err
	}
	edit := c.Method() == fiber.MethodPut
	if !edit {
		var platform string
		if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("plat").Where("id = ?", pk).Scan(&platform).Error; err != nil {
			return err
		}
		if platform == "linux" || platform == "darwin" {
			return c.Status(400).JSON("Please use 'Recover Connection' instead.")
		}
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	field, choices := "sv_action", []string{"start", "stop", "restart"}
	if edit {
		field, choices = "startType", []string{"auto", "autodelay", "manual", "disabled"}
	}
	raw, exists := input[field]
	if !exists {
		return validationError{field: {"This field is required."}}
	}
	value, messages := choiceField(raw, choices...)
	if len(messages) != 0 {
		return validationError{field: messages}
	}
	status, body, err := executeServiceWrite(c.Context(), s.NATS.Request, id, name, value, edit)
	if err != nil {
		return err
	}
	return c.Status(status).JSON(body)
}

func executeServiceWrite(ctx context.Context, request func(context.Context, string, map[string]any, time.Duration) (any, error), id, name, value string, edit bool) (int, string, error) {
	if edit {
		reply, err := request(ctx, id, map[string]any{"func": "editwinsvc", "payload": map[string]any{"name": name, "startType": value}}, 10*time.Second)
		ok, failure, err := serviceWriteAck(reply, err, true)
		if err != nil {
			return 0, "", err
		}
		if !ok {
			return 400, failure, nil
		}
		return 200, "The service start type was updated successfully", nil
	}
	actions := []string{value}
	if value == "restart" {
		actions = []string{"stop", "start"}
	}
	for _, action := range actions {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		// The second restart step is sent only after an unambiguous stop ack.
		// A timed-out command may have run; never retry either step.
		reply, err := request(ctx, id, map[string]any{"func": "winsvcaction", "payload": map[string]any{"name": name, "action": action}}, 32*time.Second)
		ok, failure, err := serviceWriteAck(reply, err, false)
		if err != nil {
			return 0, "", err
		}
		if !ok {
			return 400, failure, nil
		}
	}
	verb := map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}[value]
	return 200, "The service was " + verb + " successfully", nil
}

func serviceWriteAck(reply any, err error, edit bool) (bool, string, error) {
	if err != nil {
		if errors.Is(err, agentbus.ErrTimeout) || errors.Is(err, agentbus.ErrUnavailable) {
			return false, "Unable to contact the agent", nil
		}
		if errors.Is(err, agentbus.ErrInvalidReply) {
			return false, "", fiber.NewError(502, "Invalid agent reply.")
		}
		return false, "", err
	}
	if _, ok := reply.(string); ok {
		return false, "Unable to contact the agent", nil
	}
	data, ok := reply.(map[string]any)
	if !ok {
		return false, "", fiber.NewError(502, "Invalid agent reply.")
	}
	success, successOK := data["success"].(bool)
	message, messageOK := data["errormsg"].(string)
	if !successOK || !messageOK {
		return false, "", fiber.NewError(502, "Invalid agent reply.")
	}
	if !edit && message == "timeout" {
		return false, "Unable to contact the agent", nil
	}
	if success {
		return true, "", nil
	}
	if message != "" {
		return false, message, nil
	}
	return false, "Something went wrong", nil
}
