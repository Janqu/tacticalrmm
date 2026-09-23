package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestSNMPReadsRequireAuthentication(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerSNMPReads(app)
	for _, method := range []string{"GET", "HEAD"} {
		for _, path := range []string{"/qdt_snmp/devices/", "/qdt_snmp/latest/", "/qdt_snmp/alerts/", "/qdt_snmp/presets/", "/qdt_snmp/sites/1/probe/"} {
			response, err := app.Test(httptest.NewRequest(method, path, nil))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Fatalf("%s: got %d", method, response.StatusCode)
			}
		}
	}
}

func TestSNMPLatestResponse(t *testing.T) {
	value := 42.5
	ts := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	rows := []snmpLatestReading{
		{DeviceID: 12, Metric: "supply.black", Value: &value, Timestamp: ts},
		{DeviceID: 12, Metric: "status", Timestamp: ts},
		{DeviceID: 17, Metric: "pages.total", Value: &value, Timestamp: ts},
	}
	data, err := json.Marshal(snmpLatestResponse(rows))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"12":{"status":{"value":null,"timestamp":"2026-09-22T12:00:00Z"},"supply.black":{"value":42.5,"timestamp":"2026-09-22T12:00:00Z"}},"17":{"pages.total":{"value":42.5,"timestamp":"2026-09-22T12:00:00Z"}}}`
	if string(data) != want {
		t.Fatalf("got %s", data)
	}
	data, err = json.Marshal(snmpLatestResponse(nil))
	if err != nil || string(data) != "{}" {
		t.Fatalf("empty latest: %s, %v", data, err)
	}
}

func TestSNMPDeviceQueryScopeAndFilters(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=localhost user=unused dbname=unused"}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: db}
	for _, tc := range []struct {
		path     string
		filtered bool
		status   int
		filter   string
	}{{"/?site=3&client=4", true, 200, "d.site_id ="}, {"/?client=4", true, 200, "x.client_id ="},
		{"/?site=bad", true, 400, ""}, {"/?site=bad", false, 200, ""}} {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			c.Locals("principal", &accounts.Principal{Role: &accounts.Role{ID: 7, CanListSites: true}})
			query, err := s.snmpDeviceQuery(c, tc.filtered)
			if err != nil {
				return err
			}
			rows := []snmpDeviceRow{}
			sql := query.Select("d.id").Find(&rows).Statement.SQL.String()
			if !strings.Contains(sql, "accounts_role_can_view_clients") || !strings.Contains(sql, "accounts_role_can_view_sites") {
				t.Error("device query lost role scoping")
			}
			if tc.filter != "" && !strings.Contains(sql, tc.filter) {
				t.Errorf("missing filter %s: %s", tc.filter, sql)
			}
			if strings.Contains(tc.path, "site=3") && strings.Contains(sql, "x.client_id =") {
				t.Error("client must not override site filter")
			}
			return c.SendStatus(200)
		})
		response, err := app.Test(httptest.NewRequest("GET", tc.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s: got %d", tc.path, response.StatusCode)
		}
	}
}

func TestSNMPReadsRequireSitePermission(t *testing.T) {
	s := &Server{}
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals("principal", &accounts.Principal{Role: &accounts.Role{CanListAgents: true}})
		return c.Next()
	})
	app.Get("/devices", require("can_list_sites"), s.listSNMPDevices)
	app.Get("/latest", require("can_list_sites"), s.latestSNMPReadings)
	app.Get("/alerts", require("can_list_sites"), s.listSNMPAlerts)
	app.Get("/presets", require("can_list_sites"), s.listSNMPPresets)
	app.Get("/probe", require("can_list_sites"), s.snmpSiteProbe)
	for _, path := range []string{"/devices", "/latest", "/alerts", "/presets", "/probe"} {
		response, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatalf("missing site permission: got %d", response.StatusCode)
		}
	}
}

func TestSNMPDeviceResponse(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	recent, expired := now.Add(-29*time.Minute), now.Add(-30*time.Minute)
	problem, empty := "timeout", ""
	for _, tc := range []struct {
		seen   *time.Time
		err    *string
		status string
	}{{nil, nil, "pending"}, {nil, &empty, "pending"}, {nil, &problem, "offline"},
		{&recent, &problem, "online"}, {&expired, nil, "offline"}} {
		row := snmpDeviceRow{Community: "private-community", OfflineMinutes: 30, LastSeen: tc.seen, LastError: tc.err,
			MatrixChannels: json.RawMessage(`[]`)}
		row.prepareResponse(now)
		if row.Status != tc.status {
			t.Fatalf("status: got %s, want %s", row.Status, tc.status)
		}
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private-community") || row.Community != "•••••••••••••nity" {
			t.Fatalf("community was not masked")
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if _, present := decoded["probe_agent_name"]; present {
			t.Fatal("null probe must omit probe_agent_name, like DRF")
		}
		if decoded["probe_agent"] != nil || len(decoded["matrix_channels"].([]any)) != 0 {
			t.Fatal("unexpected null relation serialization")
		}
	}
}
