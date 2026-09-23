package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerAgentCommands(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/ping/", s.authenticate, requireRead("can_list_agents", "can_edit_agent"), s.pingAgent)
	app.Post("/checks/:agent_id/run/", s.authenticate, require("can_run_checks"), s.runAgentChecks)
	app.Post("/agents/:agent_id/wmi/", s.authenticate, require("can_edit_agent"), s.refreshAgentWMI)
	app.Post("/agents/:agent_id/reboot/", s.authenticate, require("can_reboot_agents"), s.agentPower)
	app.Post("/agents/:agent_id/shutdown/", s.authenticate, require("can_reboot_agents"), s.agentPower)
}

func (s *Server) agentPower(c fiber.Ctx) error {
	id, _, err := s.commandAgent(c)
	if err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	command := "shutdown"
	if c.Route().Path == "/agents/:agent_id/reboot/" {
		command = "rebootnow"
	}
	// A lost reply cannot prove the command was not executed; never retry.
	reply, err := s.NATS.Request(c.Context(), id, map[string]any{"func": command}, 10*time.Second)
	ack, _ := reply.(string)
	if err != nil || ack != "ok" {
		return c.Status(400).JSON("Unable to contact the agent")
	}
	return c.JSON("ok")
}

func (s *Server) refreshAgentWMI(c fiber.Ctx) error {
	id, _, err := s.commandAgent(c)
	if err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	reply, err := s.NATS.Request(c.Context(), id, map[string]any{"func": "sysinfo"}, 20*time.Second)
	ack, _ := reply.(string)
	if err != nil || ack != "ok" {
		return c.Status(400).JSON("Unable to contact the agent")
	}
	return c.JSON("Agent WMI data refreshed successfully")
}

func (s *Server) commandAgent(c fiber.Ctx) (string, string, error) {
	id, err := agentID(c)
	if err != nil {
		return "", "", err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return "", "", err
	}
	if c.Method() == fiber.MethodHead {
		return "", "", fiber.NewError(405, `Method "HEAD" not allowed.`)
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return "", "", err
	}
	var hostname string
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("hostname").Where("id = ?", pk).Scan(&hostname).Error; err != nil {
		return "", "", err
	}
	return id, hostname, nil
}

func (s *Server) pingAgent(c fiber.Ctx) error {
	id, hostname, err := s.commandAgent(c)
	if err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	status, err := pingAgentStatus(c.Context(), s.NATS.Request, id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"name": hostname, "status": status})
}

func pingAgentStatus(ctx context.Context, request func(context.Context, string, map[string]any, time.Duration) (any, error), subject string) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		reply, err := request(ctx, subject, map[string]any{"func": "ping"}, 2*time.Second)
		if err == nil {
			text, ok := reply.(string)
			if !ok {
				return "offline", nil
			} // Invalid replies must not trigger another command.
			if text == "pong" {
				return "online", nil
			}
		} else if !errors.Is(err, agentbus.ErrUnavailable) && !errors.Is(err, agentbus.ErrTimeout) {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(err, agentbus.ErrInvalidReply) {
				return "offline", nil
			}
			return "", err
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "offline", nil
}

func (s *Server) runAgentChecks(c fiber.Ctx) error {
	id, hostname, err := s.commandAgent(c)
	if err != nil {
		return err
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	// Never retry this mutation: a timed-out request may already have started the checks.
	reply, err := s.NATS.Request(c.Context(), id, map[string]any{"func": "runchecks"}, 15*time.Second)
	status, body := runChecksResponse(reply, err, hostname)
	return c.Status(status).JSON(body)
}

func runChecksResponse(reply any, err error, hostname string) (int, string) {
	if err == nil {
		text, _ := reply.(string)
		switch text {
		case "busy":
			return 400, "Checks are already running on " + hostname
		case "ok":
			return 200, "Checks will now be run on " + hostname
		}
	}
	return 400, "Unable to contact the agent"
}
