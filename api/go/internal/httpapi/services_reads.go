package httpapi

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerServiceReads(app *fiber.App) {
	methods := []string{fiber.MethodGet, fiber.MethodHead}
	app.Add(methods, "/services/:agent_id/", s.authenticate, require("can_manage_winsvcs"), s.readAgentServices)
	app.Add(methods, "/services/:agent_id/:svcname/", s.authenticate, require("can_manage_winsvcs"), s.readAgentServices)
}

func (s *Server) readAgentServices(c fiber.Ctx) error {
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
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	detail := c.Params("svcname") != ""
	payload := map[string]any{"func": "winservices"}
	if detail {
		name, err := serviceName(c)
		if err != nil {
			return err
		}
		payload = map[string]any{"func": "winsvcdetail", "payload": map[string]any{"name": name}}
	}
	reply, requestErr := s.NATS.Request(c.Context(), id, payload, 10*time.Second)
	status, reply, err := serviceReadResponse(reply, requestErr, detail)
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
	if !detail {
		// Saving only services does not trigger Agent.save's hierarchy updates.
		// A single SQL update is atomic and leaves the previous cache on failure.
		result := s.DB.WithContext(c.Context()).Exec("UPDATE agents_agent SET services = ?::jsonb WHERE id = ?", string(encoded), pk)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fiber.NewError(404, "No Agent matches the given query.")
		}
	}
	return c.Type("json").Send(encoded)
}

func serviceName(c fiber.Ctx) (string, error) {
	name, err := url.PathUnescape(c.Params("svcname"))
	if err != nil || name == "" || strings.Contains(name, "/") {
		return "", fiber.NewError(404, "Not found.")
	}
	return name, nil
}

func serviceReadResponse(reply any, err error, detail bool) (int, any, error) {
	if err != nil {
		switch {
		case errors.Is(err, agentbus.ErrTimeout):
			reply = "timeout"
		case errors.Is(err, agentbus.ErrUnavailable):
			reply = "natsdown"
		case errors.Is(err, agentbus.ErrInvalidReply):
			return 0, nil, fiber.NewError(502, "Invalid agent reply.")
		default:
			return 0, nil, err
		}
	}
	text, _ := reply.(string)
	if text == "timeout" || (!detail && text == "natsdown") {
		return 400, "Unable to contact the agent", nil
	}
	return 200, reply, nil
}
