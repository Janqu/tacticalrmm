package httpapi

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) localAccount(c fiber.Ctx) error {
	var count int64
	err := s.DB.WithContext(c.Context()).Table("socialaccount_socialaccount").Where("user_id = ?", principal(c).User.ID).Count(&count).Error
	if err != nil {
		return err
	}
	if count > 0 {
		return fiber.NewError(403, "You do not have permission to perform this action.")
	}
	return c.Next()
}

func (s *Server) setupTOTP(c fiber.Ctx) error {
	if principal(c).User.IsInstallerUser {
		return fiber.NewError(403, "You do not have permission to perform this action.")
	}
	var response any = false
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var user accounts.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, principal(c).User.ID).Error; err != nil {
			return err
		}
		if user.TOTPKey != nil && *user.TOTPKey != "" {
			return nil
		}
		if s.TOTPIssuer == "" {
			return fiber.NewError(503, "TOTP issuer is not configured.")
		}
		secret, err := accounts.GenerateTOTPKey()
		if err != nil {
			return err
		}
		// Django saves with update_fields=["totp_key"]. Audit timestamps stay unchanged.
		if err := tx.Model(&user).UpdateColumn("totp_key", secret).Error; err != nil {
			return err
		}
		response = struct {
			Username string `json:"username"`
			TOTPKey  string `json:"totp_key"`
			QRURL    string `json:"qr_url"`
		}{user.Username, secret, accounts.TOTPProvisioningURI(secret, user.Username, s.TOTPIssuer)}
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(response)
}

func (s *Server) resetPassword(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	raw, ok := input["password"]
	if !ok {
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
	if err := s.updateSelf(c, "ResetPass", map[string]any{"password": hash}); err != nil {
		return err
	}
	return c.JSON("Password was reset.")
}

func (s *Server) resetTwoFactor(c fiber.Ctx) error {
	if err := s.updateSelf(c, "Reset2FA", map[string]any{"totp_key": ""}); err != nil {
		return err
	}
	return c.JSON("2FA was reset. Log out and back in to setup.")
}

func (s *Server) userUI(c fiber.Ctx) error {
	if principal(c).User.IsInstallerUser {
		return fiber.NewError(403, "You do not have permission to perform this action.")
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	values, err := validateUserUI(s.DB.WithContext(c.Context()), input)
	if err != nil {
		return err
	}
	if err := s.updateSelf(c, "UserUI", values); err != nil {
		return err
	}
	return c.JSON("ok")
}

func (s *Server) updateSelf(c fiber.Ctx, view string, values map[string]any) error {
	return s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var before accounts.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&before, principal(c).User.ID).Error; err != nil {
			return err
		}
		return updateUser(tx, c, before, view, values)
	})
}

func updateUser(tx *gorm.DB, c fiber.Ctx, before accounts.User, view string, values map[string]any) error {
	actor := principal(c).User.Username
	values["modified_by"] = actor
	values["modified_time"] = time.Now().UTC()
	if before.CreatedBy == nil || *before.CreatedBy == "" {
		values["created_by"] = actor
	}
	if err := tx.Model(&accounts.User{}).Where("id = ?", before.ID).Updates(values).Error; err != nil {
		return err
	}
	var after accounts.User
	if err := tx.First(&after, before.ID).Error; err != nil {
		return err
	}
	// UserSerializer deliberately omits password, TOTP secret and UI colors.
	// Only changes visible to that serializer generate Django audit entries.
	beforeValue, err := userAuditValue(before)
	if err != nil {
		return err
	}
	afterValue, err := userAuditValue(after)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(beforeValue, afterValue) {
		return nil
	}
	kwargs := map[string]any{}
	if view == "GetUpdateDeleteUser" {
		kwargs["pk"] = before.ID
	}
	return audit.Write(tx, audit.Entry{
		Username: actor, ObjectType: "user", Action: "modify",
		BeforeValue: beforeValue, AfterValue: afterValue, Message: actor + " modified user " + after.Username,
		DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": view,
			"view_func": view, "view_args": []any{}, "view_kwargs": kwargs, "ip": c.IP()},
	})
}

func userAuditValue(user accounts.User) (map[string]any, error) {
	encoded, err := json.Marshal(userResponse{User: user, LastLogin: datetime(user.LastLogin)})
	if err != nil {
		return nil, err
	}
	var value map[string]any
	err = json.Unmarshal(encoded, &value)
	return value, err
}

func validateUserUI(db *gorm.DB, input map[string]json.RawMessage) (map[string]any, error) {
	values, problems := map[string]any{}, validationError{}
	for field, raw := range input {
		var value any
		var messages []string
		switch field {
		case "dark_mode", "show_community_scripts", "clear_search_when_switching", "block_dashboard_login":
			value, messages = booleanField(raw)
		case "loading_bar_color", "dash_info_color", "dash_positive_color", "dash_negative_color", "dash_warning_color":
			value, messages = charField(raw, 255, false, false)
		case "date_format":
			value, messages = charField(raw, 30, true, true)
		case "agent_dblclick_action":
			value, messages = choiceField(raw, "editagent", "takecontrol", "remotebg", "urlaction")
		case "default_agent_tbl_tab":
			value, messages = choiceField(raw, "server", "workstation", "mixed")
		case "client_tree_sort":
			value, messages = choiceField(raw, "alphafail", "alpha")
		case "client_tree_splitter":
			value, messages = positiveIntegerField(raw)
		case "url_action":
			if jsonType(raw) == "NoneType" {
				values["url_action_id"] = nil
				continue
			}
			id, errors := relatedID(raw)
			messages = errors
			if len(messages) == 0 {
				var count int64
				if err := db.Table("core_urlaction").Where("id = ?", id).Count(&count).Error; err != nil {
					return nil, err
				}
				if count == 0 {
					messages = []string{fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", id)}
				}
				values["url_action_id"] = id
			}
			if len(messages) > 0 {
				problems[field] = messages
			}
			continue
		default:
			continue // DRF serializers ignore fields outside their declared allowlist.
		}
		if len(messages) > 0 {
			problems[field] = messages
		} else {
			values[field] = value
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return values, nil
}
