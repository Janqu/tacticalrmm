package httpapi

import (
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerEventLogReads(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/eventlog/:logtype/:days<regex(^[0-9]+$)>/", s.authenticate, require("can_view_eventlogs"), s.readAgentEventLog)
}

func (s *Server) readAgentEventLog(c fiber.Ctx) error {
	name, err := url.PathUnescape(c.Params("logtype"))
	if err != nil || name == "" || strings.Contains(name, "/") {
		return fiber.NewError(404, "Not found.")
	}
	id, _, err := s.commandAgent(c)
	if err != nil {
		return err
	}
	payload, timeout, err := eventLogPayload(name, c.Params("days"))
	if err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	reply, requestErr := s.NATS.Request(c.Context(), id, payload, timeout)
	status, body, err := serviceReadResponse(reply, requestErr, false)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return fiber.NewError(502, "Invalid agent reply.")
	}
	return c.Status(status).Type("json").Send(encoded)
}

func eventLogPayload(name, rawDays string) (map[string]any, time.Duration, error) {
	// Days travels as decimal text, so do not impose a machine-integer cap.
	for _, digit := range rawDays {
		if digit < '0' || digit > '9' {
			return nil, 0, fiber.NewError(404, "Not found.")
		}
	}
	days, ok := new(big.Int).SetString(rawDays, 10)
	if !ok {
		return nil, 0, fiber.NewError(404, "Not found.")
	}
	timeout := 30
	if name == "Security" {
		timeout = 180
	}
	return map[string]any{"func": "eventlog", "timeout": timeout, "payload": map[string]any{"logname": name, "days": days.String()}}, time.Duration(timeout+2) * time.Second, nil
}
