package httpapi

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerServerMaintenance(app *fiber.App) {
	app.Post("/core/servermaintenance/", s.authenticate, require("can_do_server_maint"), s.serverMaintenance)
}

func (s *Server) serverMaintenance(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	var action string
	if json.Unmarshal(input["action"], &action) != nil {
		return c.Status(400).JSON("The data is incorrect")
	}
	switch action {
	case "reload_nats":
		return c.Status(501).JSON("Das Neuladen der NATS-Konfiguration ist in der Go-Testumgebung noch nicht verfügbar.")
	case "rm_orphaned_tasks":
		return c.Status(501).JSON("Das Entfernen verwaister Agent-Aufgaben ist in der Go-Testumgebung noch nicht verfügbar.")
	case "prune_db":
		tables, err := maintenancePruneTables(input["prune_tables"])
		if err != nil {
			return c.Status(400).JSON("The data is incorrect.")
		}
		var count int64
		if len(tables) > 0 {
			err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
				count, err = pruneMaintenanceTables(tx, tables)
				return err
			})
			if err != nil {
				return err
			}
		}
		return c.JSON(fmt.Sprintf("%d records were pruned from the database", count))
	default:
		return c.Status(400).JSON("The data is incorrect")
	}
}

func maintenancePruneTables(raw json.RawMessage) (map[string]bool, error) {
	var tables []string
	if jsonType(raw) != "list" || json.Unmarshal(raw, &tables) != nil {
		return nil, fmt.Errorf("prune_tables must be a list")
	}
	selected := make(map[string]bool)
	for _, table := range tables {
		switch table {
		case "audit_logs", "pending_actions", "alerts":
			selected[table] = true
		default:
			return nil, fmt.Errorf("unsupported prune table")
		}
	}
	return selected, nil
}

func pruneMaintenanceTables(tx *gorm.DB, tables map[string]bool) (int64, error) {
	var count int64
	for _, item := range []struct{ name, sql string }{
		{"audit_logs", "DELETE FROM logs_auditlog WHERE action = 'check_run'"},
		{"pending_actions", "DELETE FROM logs_pendingaction WHERE status = 'completed'"},
	} {
		if tables[item.name] {
			result := tx.Exec(item.sql)
			if result.Error != nil {
				return 0, result.Error
			}
			count += result.RowsAffected
		}
	}
	if tables["alerts"] {
		// Django cascades Matrix deliveries and nulls SNMP references in its
		// collector. PostgreSQL's schema has no equivalent ON DELETE actions.
		// ponytail: maintenance blocks writes to these tables until commit;
		// use bounded, row-locked batches if large alert histories need it.
		for _, statement := range []string{
			"LOCK TABLE alerts_alert, alerts_matrixdelivery, qdt_snmp_snmpalert IN SHARE ROW EXCLUSIVE MODE",
			"DELETE FROM alerts_matrixdelivery",
			"UPDATE qdt_snmp_snmpalert SET alert_id = NULL WHERE alert_id IS NOT NULL",
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return 0, err
			}
		}
		result := tx.Exec("DELETE FROM alerts_alert")
		if result.Error != nil {
			return 0, result.Error
		}
		count += result.RowsAffected
	}
	return count, nil
}
