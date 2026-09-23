package httpapi

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestServerMaintenanceValidation(t *testing.T) {
	s := &Server{}
	app := fiber.New()
	app.Post("/", s.serverMaintenance)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{}`, 400}, {`{"action":42}`, 400}, {`{"action":"bad"}`, 400},
		{`{"action":"reload_nats"}`, 501}, {`{"action":"rm_orphaned_tasks"}`, 501},
		{`{"action":"prune_db"}`, 400}, {`{"action":"prune_db","prune_tables":null}`, 400},
		{`{"action":"prune_db","prune_tables":"alerts"}`, 400},
		{`{"action":"prune_db","prune_tables":["users"]}`, 400},
		{`{"action":"prune_db","prune_tables":["alerts",123]}`, 400},
		{`{"action":"prune_db","prune_tables":[]}`, 200},
	} {
		request := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
		request.Header.Set("Content-Type", "application/json")
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s: got %d want %d", tc.body, response.StatusCode, tc.status)
		}
	}
	selected, err := maintenancePruneTables(json.RawMessage(`["audit_logs","audit_logs"]`))
	if err != nil || len(selected) != 1 || !selected["audit_logs"] {
		t.Fatalf("duplicates: %v %v", selected, err)
	}
}

func TestServerMaintenancePermissions(t *testing.T) {
	s := &Server{}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerServerMaintenance(app)
	response, err := app.Test(httptest.NewRequest("POST", "/core/servermaintenance/", nil))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("anonymous status: %d", response.StatusCode)
	}
	for _, allowed := range []bool{false, true} {
		app := fiber.New()
		app.Post("/", func(c fiber.Ctx) error {
			c.Locals("principal", &accounts.Principal{Role: &accounts.Role{CanDoServerMaint: allowed}})
			return c.Next()
		}, require("can_do_server_maint"), s.serverMaintenance)
		request := httptest.NewRequest("POST", "/", strings.NewReader(`{"action":"reload_nats"}`))
		request.Header.Set("Content-Type", "application/json")
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		want := 403
		if allowed {
			want = 501
		}
		if response.StatusCode != want {
			t.Fatalf("allowed=%v got %d", allowed, response.StatusCode)
		}
	}
}

// DryRun never connects to PostgreSQL or executes maintenance statements.
func TestMaintenancePruneSQL(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=localhost user=unused dbname=unused"}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	var statements []string
	fail := false
	if err := db.Callback().Raw().After("gorm:raw").Register("capture_maintenance", func(tx *gorm.DB) {
		statement := tx.Statement.SQL.String()
		statements = append(statements, statement)
		tx.RowsAffected = 2
		if fail {
			tx.AddError(errors.New("injected statement failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	selected := map[string]bool{"audit_logs": true, "pending_actions": true, "alerts": true}
	count, err := pruneMaintenanceTables(db, selected)
	if err != nil || count != 6 {
		t.Fatalf("primary row count %d: %v", count, err)
	}
	want := []string{
		"DELETE FROM logs_auditlog WHERE action = 'check_run'",
		"DELETE FROM logs_pendingaction WHERE status = 'completed'",
		"LOCK TABLE alerts_alert, alerts_matrixdelivery, qdt_snmp_snmpalert IN SHARE ROW EXCLUSIVE MODE",
		"DELETE FROM alerts_matrixdelivery",
		"UPDATE qdt_snmp_snmpalert SET alert_id = NULL WHERE alert_id IS NOT NULL",
		"DELETE FROM alerts_alert",
	}
	if !reflect.DeepEqual(statements, want) {
		t.Fatalf("unsafe deletion order/filter: %v", statements)
	}
	statements = nil
	fail = true
	if _, err := pruneMaintenanceTables(db, selected); err == nil || len(statements) != 1 {
		t.Fatalf("must stop on statement error: %v %v", statements, err)
	}
}
