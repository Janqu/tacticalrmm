package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

func TestHealthReportFilters(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	app.Get("/", func(c fiber.Ctx) error {
		filters, err := healthReportFilters(c)
		if err != nil {
			return err
		}
		return c.JSON(filters)
	})
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"", 200}, {"?template=health&monitoring_type=all&patch_days=30&ram_below_gb=8&disk_free_below_percent=10&software_query=", 200},
		{"?patch_days=0", 400}, {"?patch_days=366", 400}, {"?patch_days=bad", 400}, {"?monitoring_type=other", 400},
		{"?site_id=-1", 400}, {"?site_id=", 200}, {"?template=unknown", 400}, {"?ram_below_gb=4097", 400},
		{"?disk_free_below_percent=101", 400}, {"?software_query=" + strings.Repeat("x", 121), 400},
		{"?patch_days=1&patch_days=7.0", 200},
	} {
		res, err := app.Test(httptest.NewRequest("GET", "/"+tc.query, nil))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("%s: %d", tc.query, res.StatusCode)
		}
	}
	app.Get("/unsupported", s.reportHealth)
	res, err := app.Test(httptest.NewRequest("GET", "/unsupported?template=printers", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 501 {
		t.Fatalf("unsupported template status: %d", res.StatusCode)
	}
}

func TestEmptyHealthReportContract(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	filters := fiber.Map{"template": "health", "patch_days": int64(30)}
	report, err := buildGoHealthReport(nil, reportSiteOption{ID: 1, Name: "Test"}, []reportSiteOption{}, nil, filters, now)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"agents", "alerts", "site_scope"} {
		if rows, ok := decoded[field].([]any); !ok || len(rows) != 0 {
			t.Fatalf("%s: %#v", field, decoded[field])
		}
	}
	if decoded["patch_since"] != "2026-08-23T12:00:00Z" || decoded["alerts_truncated"] != false {
		t.Fatal(decoded)
	}
	for key, value := range decoded["summary"].(map[string]any) {
		if value != float64(0) {
			t.Fatalf("%s=%v", key, value)
		}
	}
}
