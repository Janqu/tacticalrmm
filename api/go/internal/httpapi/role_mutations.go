package httpapi

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/amidaware/tacticalrmm/api/go/internal/mesh"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) mutateRole(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	deleting := c.Method() == fiber.MethodDelete
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var before accounts.Role
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&before, id).Error; err != nil {
			return lookupError(err, "Role")
		}
		actor := principal(c).User.Username
		entry := audit.Entry{Username: actor, ObjectType: "role",
			DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": "GetUpdateDeleteRole",
				"view_func": "GetUpdateDeleteRole", "view_args": []any{}, "view_kwargs": map[string]any{"pk": id}, "ip": c.IP()}}
		if deleting {
			// Django's collector applies SET_NULL without calling User.save().
			if err := tx.Model(&accounts.User{}).Where("role_id = ?", id).UpdateColumn("role_id", nil).Error; err != nil {
				return err
			}
			if err := setRoleRelations(tx, id, []int64{}, []int64{}); err != nil {
				return err
			}
			if err := tx.Delete(&before).Error; err != nil {
				return err
			}
			before.ID = 0 // BaseAuditModel serializes the deleted instance, whose pk is None.
			value, err := roleAuditValue(tx, before)
			if err != nil {
				return err
			}
			value["id"] = nil
			entry.Action, entry.BeforeValue, entry.Message = "delete", value, actor+" deleted role "+before.Name
			if err := audit.Write(tx, entry); err != nil {
				return err
			}
		} else {
			input, err := jsonObject(c)
			if err != nil {
				return err
			}
			after, clients, sites, err := validateRole(tx, input, before)
			if err != nil {
				return err
			}
			entry.BeforeValue, err = roleAuditValue(tx, before)
			if err != nil {
				return err
			}
			// Django audits before assigning save metadata and before updating M2M scopes.
			entry.AfterValue, err = roleAuditValue(tx, after)
			if err != nil {
				return err
			}
			entry.Action, entry.Message = "modify", actor+" modified role "+after.Name
			if !reflect.DeepEqual(entry.BeforeValue, entry.AfterValue) {
				if err := audit.Write(tx, entry); err != nil {
					return err
				}
			}
			now := time.Now().UTC()
			after.ModifiedTime, after.ModifiedBy = &now, &actor
			if after.CreatedBy == nil || *after.CreatedBy == "" {
				after.CreatedBy = &actor
			}
			// Select includes explicit false flags and nullable audit fields.
			if err := tx.Model(&accounts.Role{}).Where("id = ?", id).Select("*").Omit("id").Updates(&after).Error; err != nil {
				return err
			}
			if err := setRoleRelations(tx, id, clients, sites); err != nil {
				return err
			}
		}
		return mesh.Enqueue(tx)
	})
	if err != nil {
		return roleWriteError(err)
	}
	if deleting {
		return c.JSON("Role was removed")
	}
	return c.JSON("Role was edited")
}

func roleAuditValue(tx *gorm.DB, role accounts.Role) (map[string]any, error) {
	projection := roleResponse{Role: role, CreatedTime: datetime(role.CreatedTime), ModifiedTime: datetime(role.ModifiedTime),
		CanViewClients: []int64{}, CanViewSites: []int64{}}
	if role.ID != 0 {
		if err := tx.Table("clients_client AS c").Select("c.id").
			Joins("JOIN accounts_role_can_view_clients AS r ON r.client_id = c.id").Where("r.role_id = ?", role.ID).
			Order("c.name").Scan(&projection.CanViewClients).Error; err != nil {
			return nil, err
		}
		if err := tx.Table("clients_site AS s").Select("s.id").
			Joins("JOIN accounts_role_can_view_sites AS r ON r.site_id = s.id").Where("r.role_id = ?", role.ID).
			Order("s.name").Scan(&projection.CanViewSites).Error; err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	delete(value, "user_count")
	return value, nil
}
