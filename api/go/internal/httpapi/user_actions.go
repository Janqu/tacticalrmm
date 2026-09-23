package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Both Django URL aliases dispatch POST to password reset and PUT to TOTP reset.
func (s *Server) userAction(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	raw, exists := input["id"]
	if !exists {
		return validationError{"id": {"This field is required."}}
	}
	id, messages := relatedID(raw)
	if len(messages) > 0 {
		return validationError{"id": messages}
	}
	actor := principal(c)
	if id != actor.User.ID && !actor.Can("can_manage_accounts") {
		return fiber.NewError(403, "You do not have permission to perform this action.")
	}
	var response string
	status := 200
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		// LocalUserPerms applies to self-resets too, and precedes target lookup.
		var core struct {
			ID                  int64
			BlockLocalUserLogon bool
		}
		if err := tx.Table("core_coresettings").Order("id").First(&core).Error; err != nil {
			return errors.New("account settings unavailable")
		}
		if core.BlockLocalUserLogon {
			return fiber.NewError(403, "You do not have permission to perform this action.")
		}
		var user accounts.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
			return lookupError(err, "User")
		}
		if s.RootUser != "" && user.Username == s.RootUser && user.ID != actor.User.ID {
			status, response = 400, "The root user cannot be modified from the UI"
			return nil
		}
		values := map[string]any{"totp_key": ""}
		response = fmt.Sprintf("%s's Two-Factor key was reset. Have them sign in again to setup", user.Username)
		if c.Method() == fiber.MethodPost {
			raw, exists := input["password"]
			if !exists {
				return validationError{"password": {"This field is required."}}
			}
			var password *string
			if err := json.Unmarshal(raw, &password); err != nil {
				return validationError{"password": {"Not a valid string."}}
			}
			hash, err := accounts.PasswordHash(password)
			if err != nil {
				return err
			}
			values, response = map[string]any{"password": hash}, "ok"
		}
		return updateUser(tx, c, user, "UserActions", values)
	})
	if err != nil {
		return err
	}
	return c.Status(status).JSON(response)
}
