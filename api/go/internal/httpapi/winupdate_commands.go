package httpapi

import (
	"errors"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) registerWinUpdateCommands(app *fiber.App) {
	app.Add([]string{fiber.MethodPost, fiber.MethodGet, fiber.MethodHead, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete}, "/winupdate/:agent_id/scan/", s.authenticate, require("can_manage_winupdates"), s.scanWinUpdates)
	app.Add([]string{fiber.MethodPost, fiber.MethodGet, fiber.MethodHead, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete}, "/winupdate/:agent_id/install/", s.authenticate, require("can_manage_winupdates"), s.installWinUpdates)
}

// installGUIDPayload preserves null GUIDs and duplicates exactly as the source values_list does.
func installGUIDPayload(guids []*string) []any {
	out := make([]any, len(guids))
	for i, guid := range guids {
		if guid != nil {
			out[i] = *guid
		}
	}
	return out
}

func (s *Server) scanWinUpdates(c fiber.Ctx) error {
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
	var agent struct{ Hostname, Plat string }
	db := s.DB.WithContext(c.Context())
	if err := db.Table("agents_agent").Select("hostname,plat").Where("id = ?", pk).Take(&agent).Error; err != nil {
		return lookupError(err, "Agent")
	}
	if agent.Plat == "linux" || agent.Plat == "darwin" {
		return c.Status(400).JSON("Not available for " + agent.Plat)
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		// Go scan callbacks use the same agent lock. Commit before publication:
		// the agent may return its inventory immediately on another connection.
		if err := tx.Table("agents_agent").Select("hostname,plat").Where("id = ?", pk).Clauses(clause.Locking{Strength: "UPDATE"}).Take(&agent).Error; err != nil {
			return lookupError(err, "Agent")
		}
		if agent.Plat == "linux" || agent.Plat == "darwin" {
			return fiber.NewError(400, "Not available for "+agent.Plat)
		}
		return pruneSupersededUpdates(tx, pk)
	})
	if err != nil {
		return err
	}
	err = s.NATS.Publish(c.Context(), id, map[string]any{"func": "getwinupdates"}, 10*time.Second)
	if err != nil {
		var failure *agentbus.PublishError
		if errors.As(err, &failure) && failure.Ambiguous {
			return c.Status(502).JSON("The scan request may have been sent; delivery could not be confirmed.")
		}
		return c.Status(503).JSON("Unable to publish the Windows update scan request.")
	}
	return c.JSON("A Windows update scan will be performed on " + agent.Hostname)
}

// Install refuses POSIX agents before mutation. Django's install view omits that
// check; the rejection is an intentional safety difference.
func (s *Server) installWinUpdates(c fiber.Ctx) error {
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
	var agent struct{ Hostname, Plat string }
	db := s.DB.WithContext(c.Context())
	if err := db.Table("agents_agent").Select("hostname,plat").Where("id = ?", pk).Take(&agent).Error; err != nil {
		return lookupError(err, "Agent")
	}
	if agent.Plat == "linux" || agent.Plat == "darwin" {
		return c.Status(400).JSON("Not available for " + agent.Plat)
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	var guids []*string
	user := principal(c).User
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Table("agents_agent").Select("hostname,plat").Where("id = ?", pk).Clauses(clause.Locking{Strength: "UPDATE"}).Take(&agent).Error; err != nil {
			return lookupError(err, "Agent")
		}
		if agent.Plat == "linux" || agent.Plat == "darwin" {
			return fiber.NewError(400, "Not available for "+agent.Plat)
		}
		if err := pruneSupersededUpdates(tx, pk); err != nil {
			return err
		}
		if _, err := approveAgentUpdates(tx, id, &patchPolicyAuditContext{
			Username:  user.Username,
			DebugInfo: debugInfo(c, "InstallWindowsUpdates", map[string]any{"agent_id": id}),
		}); err != nil {
			return err
		}
		var err error
		guids, err = approvedUpdateGUIDs(tx, pk)
		return err
	})
	if err != nil {
		return err
	}
	err = s.NATS.Publish(c.Context(), id, map[string]any{
		"func":  "installwinupdates",
		"guids": installGUIDPayload(guids),
	}, 10*time.Second)
	if err != nil {
		var failure *agentbus.PublishError
		if errors.As(err, &failure) && failure.Ambiguous {
			return c.Status(502).JSON("The install request may have been sent; delivery could not be confirmed.")
		}
		return c.Status(503).JSON("Unable to publish the Windows update install request.")
	}
	return c.JSON("Approved patches will now be installed on " + agent.Hostname)
}
