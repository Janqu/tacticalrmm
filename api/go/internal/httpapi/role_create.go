package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

func (s *Server) addRole(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		role, clients, sites, err := validateRole(tx, input, accounts.Role{})
		if err != nil {
			return err
		}
		// BaseAuditModel serializes the unsaved role before setting audit fields
		// and before ModelSerializer writes either many-to-many relationship.
		raw, err := json.Marshal(role)
		if err != nil {
			return err
		}
		var after map[string]any
		if err := json.Unmarshal(raw, &after); err != nil {
			return err
		}
		after["id"] = nil
		after["can_view_clients"], after["can_view_sites"] = []int64{}, []int64{}
		actor := principal(c).User.Username
		if err := audit.Write(tx, audit.Entry{Username: actor, ObjectType: "role", Action: "add", Message: actor + " added role " + role.Name, AfterValue: after,
			DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": "GetAddRoles", "view_func": "GetAddRoles", "view_args": []any{}, "view_kwargs": map[string]any{}, "ip": c.IP()}}); err != nil {
			return err
		}
		now := time.Now().UTC()
		role.CreatedTime, role.ModifiedTime, role.ModifiedBy = &now, &now, &actor
		if role.CreatedBy == nil || *role.CreatedBy == "" {
			role.CreatedBy = &actor
		}
		if err := tx.Create(&role).Error; err != nil {
			return err
		}
		return setRoleRelations(tx, role.ID, clients, sites)
	})
	if err != nil {
		return roleWriteError(err)
	}
	return c.JSON("Role was added")
}

func roleWriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" && strings.Contains(pg.ConstraintName, "name") {
		return validationError{"name": {"role with this name already exists."}}
	}
	return err
}

func setRoleRelations(tx *gorm.DB, roleID int64, clients, sites []int64) error {
	for _, relation := range []struct {
		table, column string
		ids           []int64
	}{
		{"accounts_role_can_view_clients", "client_id", clients},
		{"accounts_role_can_view_sites", "site_id", sites},
	} {
		if relation.ids == nil {
			continue
		} // Omitted serializer fields preserve existing scopes.
		if err := tx.Exec("DELETE FROM "+relation.table+" WHERE role_id = ?", roleID).Error; err != nil {
			return err
		}
		if len(relation.ids) == 0 {
			continue
		}
		rows := make([]map[string]any, 0, len(relation.ids))
		for _, id := range relation.ids {
			rows = append(rows, map[string]any{"role_id": roleID, relation.column: id})
		}
		if err := tx.Table(relation.table).Create(&rows).Error; err != nil {
			return err
		}
	}
	return nil
}

func validateRole(tx *gorm.DB, input map[string]json.RawMessage, role accounts.Role) (accounts.Role, []int64, []int64, error) {
	problems := validationError{}
	if raw, ok := input["name"]; ok {
		name, messages := charField(raw, 255, false, false)
		if len(messages) > 0 {
			problems["name"] = messages
		} else {
			role.Name = *name
			var count int64
			if err := tx.Model(&accounts.Role{}).Where("name = ? AND id <> ?", role.Name, role.ID).Count(&count).Error; err != nil {
				return role, nil, nil, err
			}
			if count > 0 {
				problems["name"] = []string{"role with this name already exists."}
			}
		}
	} else {
		problems["name"] = []string{"This field is required."}
	}
	// The typed Role projection is the allowlist; ignore undeclared input.
	fields := reflect.ValueOf(&role).Elem()
	for i := 0; i < fields.NumField(); i++ {
		if fields.Field(i).Kind() != reflect.Bool {
			continue
		}
		name := fields.Type().Field(i).Tag.Get("json")
		if raw, exists := input[name]; exists {
			value, messages := booleanField(raw)
			if len(messages) > 0 {
				problems[name] = messages
			} else {
				fields.Field(i).SetBool(value)
			}
		}
	}
	for field, target := range map[string]**string{"created_by": &role.CreatedBy, "modified_by": &role.ModifiedBy} {
		if raw, exists := input[field]; exists {
			value, messages := charField(raw, 255, true, true)
			if len(messages) > 0 {
				problems[field] = messages
			} else {
				*target = value
			}
		}
	}
	clients, messages, err := roleRelation(tx, input, "can_view_clients", "clients_client")
	if err != nil {
		return role, nil, nil, err
	}
	if len(messages) > 0 {
		problems["can_view_clients"] = messages
	}
	sites, messages, err := roleRelation(tx, input, "can_view_sites", "clients_site")
	if err != nil {
		return role, nil, nil, err
	}
	if len(messages) > 0 {
		problems["can_view_sites"] = messages
	}
	if len(problems) > 0 {
		return role, nil, nil, problems
	}
	return role, clients, sites, nil
}

func roleRelation(tx *gorm.DB, input map[string]json.RawMessage, field, table string) ([]int64, []string, error) {
	raw, exists := input[field]
	if !exists {
		return nil, nil, nil
	}
	if jsonType(raw) == "NoneType" {
		return nil, []string{"This field may not be null."}, nil
	}
	var items []json.RawMessage
	if jsonType(raw) == "dict" {
		// DRF treats dictionaries as iterables of keys, in their input order.
		decoder := json.NewDecoder(bytes.NewReader(raw))
		if _, err := decoder.Token(); err != nil {
			return nil, nil, err
		}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, nil, err
			}
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return nil, nil, err
			}
			item, err := json.Marshal(key)
			if err != nil {
				return nil, nil, err
			}
			items = append(items, item)
		}
	} else if json.Unmarshal(raw, &items) != nil {
		return nil, []string{fmt.Sprintf("Expected a list of items but got type \"%s\".", jsonType(raw))}, nil
	}
	ids := make([]int64, 0, len(items))
	seen := map[int64]bool{}
	checks := make([]struct {
		id       int64
		messages []string
	}, len(items))
	for i, item := range items {
		id, messages := relatedID(item)
		if jsonType(item) == "NoneType" {
			messages = []string{"Invalid pk \"None\" - object does not exist."}
		}
		checks[i].id, checks[i].messages = id, messages
		if len(messages) > 0 {
			continue
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	var found []int64
	if len(ids) > 0 {
		if err := tx.Table(table).Where("id IN ?", ids).Pluck("id", &found).Error; err != nil {
			return nil, nil, err
		}
	}
	for _, id := range found {
		delete(seen, id)
	}
	for _, check := range checks {
		if len(check.messages) > 0 {
			return nil, check.messages, nil
		}
		if seen[check.id] {
			return nil, []string{fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", check.id)}, nil
		}
	}
	return ids, nil, nil
}
