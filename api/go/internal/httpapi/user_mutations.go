package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/amidaware/tacticalrmm/api/go/internal/mesh"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) updateAccount(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	rootProtected := false
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var before accounts.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&before, id).Error; err != nil {
			return lookupError(err, "User")
		}
		if s.RootUser != "" && before.Username == s.RootUser && id != principal(c).User.ID {
			rootProtected = true
			return nil
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		values, err := validateAccount(tx, input, id)
		if err != nil {
			return err
		}
		if err := updateUser(tx, c, before, "GetUpdateDeleteUser", values); err != nil {
			return err
		}
		return mesh.Enqueue(tx)
	})
	if err != nil {
		if duplicateUsername(err) {
			return validationError{"username": {"A user with that username already exists."}}
		}
		return err
	}
	if rootProtected {
		return c.Status(400).JSON("The root user cannot be modified from the UI")
	}
	return c.JSON("ok")
}

func duplicateUsername(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505" && strings.Contains(pg.ConstraintName, "username")
}

func (s *Server) addAccount(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	for _, field := range []string{"username", "email", "password"} {
		if _, ok := input[field]; !ok {
			return validationError{field: {"This field is required."}}
		}
	}
	var username string
	if json.Unmarshal(input["username"], &username) != nil || jsonType(input["username"]) != "str" {
		return validationError{"username": {"Not a valid string."}}
	}
	if !validUsername(username) {
		return c.Status(400).JSON("['" + invalidUsername + "']")
	}
	var email, password *string
	if err := json.Unmarshal(input["email"], &email); err != nil {
		return validationError{"email": {"Not a valid string."}}
	}
	if err := json.Unmarshal(input["password"], &password); err != nil {
		return validationError{"password": {"Not a valid string."}}
	}
	user := accounts.User{Username: norm.NFKC.String(username), IsActive: true}
	if email != nil {
		user.Email = *email
		trimmed := strings.TrimSpace(*email)
		if at := strings.LastIndexByte(trimmed, '@'); at >= 0 {
			user.Email = trimmed[:at+1] + cases.Lower(language.Und).String(trimmed[at+1:])
		}
	}
	// The Python create view bypasses serializer validation. Bound storage fields
	// here so malformed input cannot fail after creating part of an account.
	for field, value := range map[string]string{"username": user.Username, "email": user.Email} {
		limit := 150
		if field == "email" {
			limit = 254
		}
		if utf8.RuneCountInString(value) > limit {
			return validationError{field: {fmt.Sprintf("Ensure this field has no more than %d characters.", limit)}}
		}
		if strings.ContainsRune(value, 0) {
			return validationError{field: {"Null characters are not allowed."}}
		}
	}
	values := map[string]any{}
	for _, field := range []string{"first_name", "last_name"} {
		if raw, exists := input[field]; exists {
			var value string
			if json.Unmarshal(raw, &value) != nil || jsonType(raw) != "str" {
				return validationError{field: {"Not a valid string."}}
			}
			if utf8.RuneCountInString(value) > 150 {
				return validationError{field: {"Ensure this field has no more than 150 characters."}}
			}
			if strings.ContainsRune(value, 0) {
				return validationError{field: {"Null characters are not allowed."}}
			}
			values[field] = value
		}
	}
	user.Password, err = accounts.PasswordHash(password)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		if raw, exists := input["role"]; exists && (jsonType(raw) == "int" || jsonType(raw) == "bool") {
			if string(raw) == "true" {
				raw = json.RawMessage("1")
			}
			if string(raw) == "false" {
				raw = json.RawMessage("0")
			}
			id, messages := relatedID(raw)
			if len(messages) > 0 {
				return validationError{"role": messages}
			}
			var role accounts.Role
			if err := tx.First(&role, id).Error; err != nil {
				return lookupError(err, "Role")
			}
			values["role_id"] = id
		}
		after, err := userAuditValue(user)
		if err != nil {
			return err
		}
		after["id"] = nil
		actor := principal(c).User.Username
		if err := audit.Write(tx, audit.Entry{Username: actor, ObjectType: "user", Action: "add",
			AfterValue: after, Message: actor + " added user " + user.Username,
			DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": "GetAddUsers", "view_func": "GetAddUsers",
				"view_args": []any{}, "view_kwargs": map[string]any{}, "ip": c.IP()}}); err != nil {
			return err
		}
		now := time.Now().UTC()
		row := map[string]any{
			"username": user.Username, "email": user.Email, "password": user.Password, "first_name": "", "last_name": "",
			"is_active": true, "is_staff": false, "is_superuser": false, "date_joined": now,
			"created_by": actor, "modified_by": actor, "created_time": now, "modified_time": now,
			"block_dashboard_login": false, "dark_mode": true, "show_community_scripts": true,
			"agent_dblclick_action": "editagent", "default_agent_tbl_tab": "mixed", "agents_per_page": 50,
			"client_tree_sort": "alphafail", "client_tree_splitter": 11, "loading_bar_color": "red",
			"dash_info_color": "info", "dash_positive_color": "positive", "dash_negative_color": "negative",
			"dash_warning_color": "warning", "clear_search_when_switching": true, "is_installer_user": false,
		}
		if err := tx.Table("accounts_user").Create(row).Error; err != nil {
			return err
		}
		if err := tx.Where("username = ?", user.Username).First(&user).Error; err != nil {
			return err
		}
		if err := updateUser(tx, c, user, "GetAddUsers", values); err != nil {
			return err
		}
		return mesh.Enqueue(tx)
	})
	if err != nil {
		if duplicateUsername(err) {
			return c.Status(400).JSON("ERROR: User " + username + " already exists!")
		}
		return err
	}
	return c.JSON(user.Username)
}
