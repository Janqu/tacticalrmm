package httpapi

import (
	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/amidaware/tacticalrmm/api/go/internal/mesh"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) deleteUser(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	status, response := 200, "ok"
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var user accounts.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
			return lookupError(err, "User")
		}
		actor := principal(c).User
		if s.RootUser != "" && user.Username == s.RootUser && user.ID != actor.ID {
			status, response = 400, "The root user cannot be deleted from the UI"
			return nil
		}
		// Django's collector executes these cascades itself; its PostgreSQL
		// foreign keys do not implement ON DELETE CASCADE or SET NULL.
		// Cascaded BaseAuditModel instances do not invoke their delete methods.
		statements := []string{
			`DELETE FROM clients_deployment WHERE auth_token_id IN (SELECT digest FROM knox_authtoken WHERE user_id = ?)`,
			`DELETE FROM account_emailconfirmation WHERE email_address_id IN (SELECT id FROM account_emailaddress WHERE user_id = ?)`,
			`DELETE FROM socialaccount_socialtoken WHERE account_id IN (SELECT id FROM socialaccount_socialaccount WHERE user_id = ?)`,
			`DELETE FROM core_aichatmessage WHERE session_id IN (SELECT id FROM core_aichatsession WHERE user_id = ?)`,
			`DELETE FROM qdt_reports_reportdelivery_matrix_channels WHERE reportdelivery_id IN (SELECT id FROM qdt_reports_reportdelivery WHERE owner_id = ?)`,
			`DELETE FROM authtoken_token WHERE user_id = ?`,
			`DELETE FROM knox_authtoken WHERE user_id = ?`,
			`DELETE FROM accounts_user_groups WHERE user_id = ?`,
			`DELETE FROM accounts_user_user_permissions WHERE user_id = ?`,
			`DELETE FROM accounts_apikey WHERE user_id = ?`,
			`DELETE FROM account_emailaddress WHERE user_id = ?`,
			`DELETE FROM socialaccount_socialaccount WHERE user_id = ?`,
			`DELETE FROM agents_pushtoken WHERE user_id = ?`,
			`DELETE FROM qdt_reports_reportconfiguration WHERE owner_id = ?`,
			`DELETE FROM qdt_reports_reportrun WHERE owner_id = ?`,
			`DELETE FROM qdt_reports_reportdelivery WHERE owner_id = ?`,
			`DELETE FROM core_aichatsession WHERE user_id = ?`,
			`UPDATE agents_note SET user_id = NULL WHERE user_id = ?`,
			`UPDATE qdt_inventory_assetevent SET actor_id = NULL WHERE actor_id = ?`,
			`UPDATE qdt_inventory_assetattachment SET uploaded_by_id = NULL WHERE uploaded_by_id = ?`,
			`DELETE FROM accounts_user WHERE id = ?`,
		}
		for _, statement := range statements {
			if err := tx.Exec(statement, id).Error; err != nil {
				return err
			}
		}
		value, err := userAuditValue(user)
		if err != nil {
			return err
		}
		value["id"] = nil // Django audits the deleted instance after clearing its pk.
		if err := audit.Write(tx, audit.Entry{
			Username: actor.Username, ObjectType: "user", Action: "delete", BeforeValue: value,
			Message: actor.Username + " deleted user " + user.Username,
			DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": "GetUpdateDeleteUser",
				"view_func": "GetUpdateDeleteUser", "view_args": []any{}, "view_kwargs": map[string]any{"pk": id}, "ip": c.IP()},
		}); err != nil {
			return err
		}
		return mesh.Enqueue(tx)
	})
	if err != nil {
		return err
	}
	return c.Status(status).JSON(response)
}
