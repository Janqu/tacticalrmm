package httpapi

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerAgentProcesses(app *fiber.App) {
	permission := require("can_manage_procs")
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/processes/", s.authenticate, permission, s.agentProcesses)
	app.Delete("/agents/:agent_id/processes/:pid<regex(^[0-9]+$)>/", s.authenticate, permission, s.agentProcesses)
}

func (s *Server) agentProcesses(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	if _, err := s.agentPK(c, id); err != nil {
		return err
	}
	payload := map[string]any{"func": "procs"}
	timeout := 5 * time.Second
	var pid uint64
	kill := c.Method() == fiber.MethodDelete
	if kill {
		pid, err = parseProcessPID(c.Params("pid"))
		if err != nil {
			return err
		}
		payload = map[string]any{"func": "killproc", "procpid": pid}
		timeout = 15 * time.Second
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	// A failed reply cannot establish whether a process was killed: never retry.
	reply, err := s.NATS.Request(c.Context(), id, payload, timeout)
	status, body := processCommandResponse(reply, err, kill, pid)
	return c.Status(status).JSON(body)
}

func parseProcessPID(raw string) (uint64, error) {
	// Django's nonnegative URL integer is serialized by MessagePack; uint64 is its wire limit.
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, validationError{"pid": {"A valid non-negative 64-bit process ID is required."}}
	}
	return value, nil
}

func processCommandResponse(reply any, err error, kill bool, pid uint64) (int, any) {
	if errors.Is(err, agentbus.ErrUnavailable) || errors.Is(err, agentbus.ErrTimeout) {
		return 400, "Unable to contact the agent"
	}
	if err != nil {
		return 502, fiber.Map{"detail": "Invalid response from the agent."}
	}
	text, isString := reply.(string)
	if isString && (text == "timeout" || text == "natsdown") {
		return 400, "Unable to contact the agent"
	}
	if kill {
		if !isString {
			return 502, fiber.Map{"detail": "Invalid response from the agent."}
		}
		if text != "ok" {
			return 400, text
		}
		return 200, "Process with PID: " + strconv.FormatUint(pid, 10) + " was ended successfully"
	}
	entries, ok := reply.([]any)
	if !ok {
		return 502, fiber.Map{"detail": "Invalid response from the agent."}
	}
	for _, entry := range entries {
		if _, ok := entry.(map[string]any); !ok {
			return 502, fiber.Map{"detail": "Invalid response from the agent."}
		}
	}
	if _, err := json.Marshal(entries); err != nil {
		return 502, fiber.Map{"detail": "Invalid response from the agent."}
	}
	return 200, entries
}
