package httpapi

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerSoftwareWrites(app *fiber.App) {
	app.Add([]string{fiber.MethodPost, fiber.MethodPut}, "/software/:agent_id/", s.authenticate, require("can_manage_software"), s.writeAgentSoftware)
}

func (s *Server) writeAgentSoftware(c fiber.Ctx) error {
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
	var agent struct{ Hostname, Plat string }
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("hostname,plat").Where("id = ?", pk).Scan(&agent).Error; err != nil {
		return err
	}
	if agent.Plat == "linux" || agent.Plat == "darwin" {
		return c.Status(400).JSON("Not available for " + agent.Plat)
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	if c.Method() == fiber.MethodPut {
		return s.refreshAgentSoftware(c, id, pk)
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	name, err := softwareInstallName(input["name"])
	if err != nil {
		return err
	}
	details, err := json.Marshal(map[string]any{"name": name, "output": nil, "installed": false})
	if err != nil {
		return err
	}
	var pendingID int64
	// Commit before publishing: the agent can immediately update this row.
	err = s.DB.WithContext(c.Context()).Raw("INSERT INTO logs_pendingaction (agent_id,entry_time,action_type,status,details) VALUES (?, ?, 'chocoinstall', 'pending', ?::jsonb) RETURNING id", pk, time.Now().UTC(), string(details)).Scan(&pendingID).Error
	if err != nil {
		return err
	}
	reply, requestErr := s.NATS.Request(c.Context(), id, map[string]any{"func": "installwithchoco", "choco_prog_name": name, "pending_action_pk": pendingID}, 2*time.Second)
	accepted, replyErr := softwareInstallAck(reply, requestErr)
	if !accepted {
		// Preserve ambiguous attempts: the agent may have started installation
		// before its response was lost. A completed callback is never removed.
		if softwareInstallRejected(reply, requestErr) {
			if err := s.DB.WithContext(c.Context()).Exec("DELETE FROM logs_pendingaction WHERE id = ? AND agent_id = ? AND status = 'pending'", pendingID, pk).Error; err != nil {
				return err
			}
		}
		// Never resend or conceal a cleanup failure as successful cancellation.
		if replyErr != nil {
			return replyErr
		}
		return c.Status(400).JSON("Unable to contact the agent")
	}
	return c.JSON(name + " will be installed shortly on " + agent.Hostname + ". Check the Pending Actions menu to see the status/output")
}

func softwareInstallRejected(reply any, err error) bool {
	text, ok := reply.(string)
	return err == nil && ok && text != "ok" && text != "timeout" && text != "natsdown"
}

func softwareInstallName(raw json.RawMessage) (string, error) {
	var name string
	if json.Unmarshal(raw, &name) != nil || strings.TrimSpace(name) == "" {
		return "", validationError{"name": {"A non-empty package name is required."}}
	}
	return name, nil
}

func softwareInstallAck(reply any, err error) (bool, error) {
	if err != nil {
		if errors.Is(err, agentbus.ErrTimeout) || errors.Is(err, agentbus.ErrUnavailable) {
			return false, nil
		}
		if errors.Is(err, agentbus.ErrInvalidReply) {
			return false, fiber.NewError(502, "Invalid agent reply.")
		}
		return false, err
	}
	text, ok := reply.(string)
	if !ok {
		return false, fiber.NewError(502, "Invalid agent reply.")
	}
	return text == "ok", nil
}

func (s *Server) refreshAgentSoftware(c fiber.Ctx, id string, pk int64) error {
	reply, requestErr := s.NATS.Request(c.Context(), id, map[string]any{"func": "softwarelist"}, 15*time.Second)
	status, reply, err := serviceReadResponse(reply, requestErr, false)
	if err != nil {
		return err
	}
	if status != 200 {
		return c.Status(status).JSON(reply)
	}
	if reply == nil {
		return fiber.NewError(502, "Invalid agent reply.")
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		return fiber.NewError(502, "Invalid agent reply.")
	}
	// Serialize Go refreshes only after the network call. Django writers do
	// not take this lock, so a mixed-runtime insert race remains possible.
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		if _, err := readRow(tx, "agents_agent", pk, true); err != nil {
			return lookupError(err, "Agent")
		}
		var softwareID int64
		if err := tx.Table("software_installedsoftware").Select("id").Where("agent_id = ?", pk).Order("id").Limit(1).Scan(&softwareID).Error; err != nil {
			return err
		}
		if softwareID == 0 {
			return tx.Exec("INSERT INTO software_installedsoftware (agent_id,software) VALUES (?, ?::jsonb)", pk, string(encoded)).Error
		}
		return tx.Exec("UPDATE software_installedsoftware SET software = ?::jsonb WHERE id = ?", string(encoded), softwareID).Error
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}
