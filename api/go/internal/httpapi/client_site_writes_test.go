package httpapi

import (
	"context"
	"encoding/json"
	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"github.com/gofiber/fiber/v3"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClientSiteAndCustomFieldWritesRequireAuthentication(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	for _, r := range [][2]string{{"POST", "/clients/"}, {"PUT", "/clients/1/"}, {"DELETE", "/clients/1/"},
		{"POST", "/clients/sites/"}, {"PUT", "/clients/sites/1/"}, {"DELETE", "/clients/sites/1/"},
		{"GET", "/core/customfields/"}, {"PATCH", "/core/customfields/"}, {"POST", "/core/customfields/"},
		{"GET", "/core/customfields/1/"}, {"PUT", "/core/customfields/1/"}, {"DELETE", "/core/customfields/1/"}} {
		response, err := app.Test(httptest.NewRequest(r[0], r[1], nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Errorf("%s %s = %d, want 401", r[0], r[1], response.StatusCode)
		}
	}
}

func TestSameClientFollowsPythonEquality(t *testing.T) {
	for raw, want := range map[string]bool{"5": true, "5.0": true, `"5"`: false, "6": false, "null": false, "true": false} {
		if got := sameClient(json.RawMessage(raw), 5); got != want {
			t.Errorf("sameClient(%s) = %v", raw, got)
		}
	}
}

func TestStringListMatchesListFieldOfCharFields(t *testing.T) {
	got, msgs := stringList(json.RawMessage(`[" a ", null, 3]`), 255, true)
	if len(msgs) > 0 || got == nil || *got != `["a",null,"3"]` {
		t.Fatalf("got %v %v", got, msgs)
	}
	if v, msgs := stringList(json.RawMessage("null"), 255, true); v != nil || len(msgs) > 0 {
		t.Fatal("null must be accepted as SQL NULL")
	}
	for _, bad := range []string{`"a"`, `{"a":1}`, `[true]`, `[[1]]`} {
		if _, msgs := stringList(json.RawMessage(bad), 255, true); len(msgs) == 0 {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, msgs := stringList(json.RawMessage("null"), 255, false); len(msgs) == 0 {
		t.Fatal("null accepted for non-null list")
	}
}

func TestInitialSetupValidationAndPermissions(t *testing.T) {
	valid := map[string]json.RawMessage{"timezone": json.RawMessage(`"Europe/Berlin"`), "companyname": json.RawMessage(`" Example "`)}
	values, err := initialSetupValues(valid)
	if err != nil || values["default_time_zone"] != "Europe/Berlin" || *values["mesh_company_name"].(*string) != "Example" {
		t.Fatalf("unexpected values: %v %v", values, err)
	}
	for _, bad := range []map[string]json.RawMessage{
		{"companyname": json.RawMessage(`"Example"`)},
		{"timezone": json.RawMessage(`"invalid/zone"`), "companyname": json.RawMessage(`"Example"`)},
		{"timezone": json.RawMessage(`"UTC"`), "companyname": json.RawMessage(`{}`)},
	} {
		if _, err := initialSetupValues(bad); err == nil {
			t.Fatal("invalid initial settings accepted")
		}
	}
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, p := range []*accounts.Principal{
		{Role: &accounts.Role{CanManageClients: true}},
		{User: accounts.User{IsSuperuser: true, IsInstallerUser: true}},
	} {
		app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
		app.Post("/clients/", func(c fiber.Ctx) error { c.Locals("principal", p); return c.Next() }, s.addClient)
		req := httptest.NewRequest("POST", "/clients/", strings.NewReader(`{"client":{"name":"Example"},"site":{"name":"HQ"},"timezone":"UTC","companyname":"Example","initialsetup":true}`))
		req.Header.Set("Content-Type", "application/json")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("initial setup without global permission: %d", res.StatusCode)
		}
	}
}

func TestInitialSetupTransaction(t *testing.T) {
	dsn := os.Getenv("INITIAL_SETUP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set INITIAL_SETUP_TEST_DATABASE_URL for PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx := db.WithContext(ctx).Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	// Temporary tables shadow real data. The failing core constraint exercises
	// rollback after both organisation rows and their audits have been inserted.
	sql := `CREATE TEMP TABLE core_coresettings (id integer PRIMARY KEY, default_time_zone text, mesh_company_name text CHECK(mesh_company_name <> 'reject-core'),modified_by text,modified_time timestamptz,smtp_host_password text);
 INSERT INTO core_coresettings VALUES (1,'UTC','',NULL,NULL,'test-redaction-value');
 CREATE TEMP TABLE clients_client (id serial PRIMARY KEY, name text UNIQUE, created_by text,created_time timestamptz,modified_by text,modified_time timestamptz,block_policy_inheritance boolean,failing_checks jsonb,workstation_policy_id integer,server_policy_id integer,alert_template_id integer);
 CREATE TEMP TABLE clients_site (id serial PRIMARY KEY,client_id integer,name text,created_by text,created_time timestamptz,modified_by text,modified_time timestamptz,block_policy_inheritance boolean,failing_checks jsonb,workstation_policy_id integer,server_policy_id integer,alert_template_id integer);
 CREATE TEMP TABLE logs_auditlog (id serial PRIMARY KEY,username text,agent text,agent_id text,entry_time timestamptz,action text,object_type text,before_value jsonb,after_value jsonb,message text,debug_info jsonb);`
	if err := tx.Exec(sql).Error; err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: tx, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	app.Post("/clients/", func(c fiber.Ctx) error {
		c.Locals("principal", &accounts.Principal{User: accounts.User{Username: "root", IsSuperuser: true}})
		return c.Next()
	}, s.addClient)
	request := func(company string) int {
		payload := map[string]any{"client": map[string]string{"name": "Example"}, "site": map[string]string{"name": "HQ"}, "initialsetup": true, "timezone": "Europe/Berlin", "companyname": company}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/clients/", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if status := request("reject-core"); status != 500 {
		t.Fatalf("constraint failure status=%d", status)
	}
	for _, table := range []string{"clients_client", "clients_site", "logs_auditlog"} {
		var count int64
		if err := tx.Table(table).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s was partially committed", table)
		}
	}
	if status := request("Example Ltd"); status != 200 {
		t.Fatalf("setup status=%d", status)
	}
	var core struct{ DefaultTimeZone, MeshCompanyName string }
	if err := tx.Table("core_coresettings").Take(&core).Error; err != nil {
		t.Fatal(err)
	}
	if core.DefaultTimeZone != "Europe/Berlin" || core.MeshCompanyName != "Example Ltd" {
		t.Fatalf("settings not saved: %v", core)
	}
	for _, table := range []string{"clients_client", "clients_site"} {
		var count int64
		if err := tx.Table(table).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s count=%d", table, count)
		}
	}
	var audit string
	if err := tx.Raw("SELECT after_value::text FROM logs_auditlog WHERE object_type='coresettings'").Scan(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "test-redaction-value") || !strings.Contains(audit, "[redacted]") {
		t.Fatal("core audit must redact secrets")
	}
}
