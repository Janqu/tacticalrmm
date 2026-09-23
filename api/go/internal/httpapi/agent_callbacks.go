package httpapi

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerAgentCallbacks(app *fiber.App) {
	app.Add([]string{fiber.MethodPatch, fiber.MethodGet, fiber.MethodHead, fiber.MethodPost, fiber.MethodPut, fiber.MethodDelete}, "/api/v4/:agentid/:pk<regex(^[0-9]+$)>/chocoresult/", s.authenticateAgentCallback, s.chocoResultCallback)
}

type agentCallbackPrincipalKey struct{}

func (s *Server) authenticateAgentCallback(c fiber.Ctx) error {
	user, err := accounts.AuthenticateAgentToken(c.Context(), s.DB, c.Get("Authorization"))
	if err != nil {
		return err
	}
	c.Locals(agentCallbackPrincipalKey{}, user)
	return c.Next()
}

func (s *Server) chocoResultCallback(c fiber.Ctx) error {
	if c.Method() != fiber.MethodPatch {
		return fiber.NewError(405, "Method \""+c.Method()+"\" not allowed.")
	}
	user := c.Locals(agentCallbackPrincipalKey{}).(*accounts.AgentTokenPrincipal)
	if user.AgentID == nil {
		return agentNotFound()
	}
	id, err := url.PathUnescape(c.Params("agentid"))
	if err != nil || strings.Contains(id, "/") {
		return fiber.NewError(404, "Not found.")
	}
	var agent struct{ AgentID string }
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("agent_id").Where("id = ?", *user.AgentID).Take(&agent).Error; err != nil {
		return lookupError(err, "Agent")
	}
	// Django ignores this URL parameter; bind it to the authenticated agent.
	if id != agent.AgentID {
		return agentNotFound()
	}
	pk, err := identifier(c)
	if err != nil {
		return err
	}
	if pk == 0 {
		return lookupError(gorm.ErrRecordNotFound, "PendingAction")
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		row, err := readRow(tx, "logs_pendingaction", pk, true)
		if err != nil {
			return lookupError(err, "PendingAction")
		}
		if pyStr(row["agent_id"]) != pyStr(*user.AgentID) || row["action_type"] != "chocoinstall" {
			return lookupError(gorm.ErrRecordNotFound, "PendingAction")
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		var results string
		if jsonType(input["results"]) != "str" || json.Unmarshal(input["results"], &results) != nil {
			return validationError{"results": {"A string is required."}}
		}
		details, ok := row["details"].(map[string]any)
		if !ok {
			return validationError{"details": {"A package name is required."}}
		}
		name, ok := details["name"].(string)
		if !ok || strings.TrimSpace(name) == "" {
			return validationError{"details": {"A package name is required."}}
		}
		details["output"], details["installed"] = results, chocoInstallSucceeded(name, results)
		encoded, err := json.Marshal(details)
		if err != nil {
			return err
		}
		return tx.Exec("UPDATE logs_pendingaction SET details = ?::jsonb,status = 'completed' WHERE id = ?", string(encoded), pk).Error
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func chocoInstallSucceeded(name, output string) bool {
	name, output = strings.ToLower(name), strings.ToLower(output)
	for _, words := range [][]string{{"install", "of", name, "was", "successful", "installed"}, {name, "already", "installed", "--force", "reinstall"}} {
		all := true
		for _, word := range words {
			if !strings.Contains(output, word) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
