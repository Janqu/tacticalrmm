package httpapi

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestReportReadPermissions(t *testing.T) {
	for _, tc := range []struct {
		user   accounts.User
		role   accounts.Role
		status int
	}{
		{role: accounts.Role{}, status: 403},
		{role: accounts.Role{CanListAgents: true}, status: 403},
		{role: accounts.Role{CanViewReports: true}, status: 204},
		{role: accounts.Role{CanManageReports: true}, status: 204},
		{user: accounts.User{IsSuperuser: true}, status: 204},
		{user: accounts.User{IsInstallerUser: true, IsSuperuser: true}, status: 403},
	} {
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			c.Locals("principal", &accounts.Principal{User: tc.user, Role: &tc.role})
			return c.Next()
		})
		app.Add([]string{"GET", "HEAD"}, "/", requireReportRead, func(c fiber.Ctx) error { return c.SendStatus(204) })
		for _, method := range []string{"GET", "HEAD"} {
			response, err := app.Test(httptest.NewRequest(method, "/", nil))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("%s role %+v: got %d", method, tc.role, response.StatusCode)
			}
		}
	}
	s := &Server{}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerReportReads(app)
	for _, path := range []string{"/qdt_reports/options/", "/qdt_reports/configurations/", "/qdt_reports/client/1/health/"} {
		response, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatalf("anonymous %s: %d", path, response.StatusCode)
		}
	}
}

func TestReportReadQueries(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=localhost user=unused dbname=unused"}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	var sql string
	var vars []any
	if err := db.Callback().Query().After("gorm:query").Register("capture_report_query", func(tx *gorm.DB) {
		sql = tx.Statement.SQL.String()
		vars = tx.Statement.Vars
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: db}
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals("principal", &accounts.Principal{User: accounts.User{ID: 42}, Role: &accounts.Role{ID: 7, CanViewReports: true}})
		return c.Next()
	})
	app.Get("/options", requireReportRead, s.reportOptions)
	app.Get("/configurations", requireReportRead, s.reportConfigurations)
	for _, tc := range []struct{ path, body string }{{"/options", `{"can_manage":false,"clients":[]}`}, {"/configurations", `[]`}} {
		response, err := app.Test(httptest.NewRequest("GET", tc.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || string(body) != tc.body {
			t.Fatalf("%s: %d %s", tc.path, response.StatusCode, body)
		}
		if tc.path == "/options" {
			for _, part := range []string{"accounts_role_can_view_clients", "accounts_role_can_view_sites", "ORDER BY parent.name, x.name"} {
				if !strings.Contains(sql, part) {
					t.Fatalf("missing %s in %s", part, sql)
				}
			}
		} else if !strings.Contains(sql, "owner_id = $1") || !strings.Contains(sql, "ORDER BY name, id") || len(vars) != 1 || vars[0] != int64(42) {
			t.Fatalf("configuration query lost owner restriction/order: %s %v", sql, vars)
		}
	}
}

func TestReportReadSerialization(t *testing.T) {
	clients := reportClientOptions([]reportSiteRow{
		{ID: 2, Name: "A", ClientID: 1, ClientName: "First"},
		{ID: 3, Name: "B", ClientID: 1, ClientName: "First"},
		{ID: 4, Name: "C", ClientID: 7, ClientName: "Second"},
	})
	if len(clients) != 2 || len(clients[0].Sites) != 2 || clients[1].ID != 7 {
		t.Fatalf("unexpected grouping: %+v", clients)
	}
	options, err := reportConfigurationOptions(json.RawMessage(`{"template":"inventory","sections":["agents"],"site_id":null,"unknown":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	if options["patch_days"] != 30 || options["monitoring_type"] != "all" || options["client_id"] != nil {
		t.Fatalf("missing defaults: %v", options)
	}
	if _, present := options["unknown"]; present {
		t.Fatal("unknown stored option leaked")
	}
	if _, present := options["site_id"]; !present {
		t.Fatal("explicit null site lost")
	}
	options, err = reportConfigurationOptions(json.RawMessage(`{"template":"health","sections":["summary"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := options["site_id"]; present {
		t.Fatal("absent optional site unexpectedly emitted")
	}
}
