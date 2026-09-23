package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestCheckDescriptions(t *testing.T) {
	script := "Probe"
	for _, tc := range []struct{ kind, want string }{
		{"diskspace", "Disk Space Check: Drive None -  Warning Threshold: 20% Error Threshold: 10%"},
		{"cpuload", "CPU Load Check -  Warning Threshold: 20% Error Threshold: 10%"},
		{"memory", "Memory Check -  Warning Threshold: 20% Error Threshold: 10%"},
		{"ping", "Ping Check: None"}, {"winsvc", "Service Check: None"},
		{"eventlog", "Event Log Check: None"}, {"script", "Script Check: Probe"}, {"other", "n/a"},
	} {
		got, err := checkDescription(map[string]any{"check_type": tc.kind, "warning_threshold": json.Number("20"), "error_threshold": json.Number("10")}, &script)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v", tc.kind, got, err)
		}
	}
	if _, err := checkDescription(map[string]any{"check_type": "script"}, nil); err == nil {
		t.Fatal("missing script must fail")
	}
}

func TestCheckReadRoutesAuthentication(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerCheckReads(app)
	for _, path := range []string{"/checks/", "/checks/1/", "/automation/policies/1/checks/", "/automation/checks/1/status/"} {
		for _, method := range []string{"GET", "HEAD"} {
			response, err := app.Test(httptest.NewRequest(method, path, nil))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Errorf("%s %s: %d", method, path, response.StatusCode)
			}
		}
	}
	response, err := app.Test(httptest.NewRequest("PATCH", "/checks/1/history/", nil))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal(response.StatusCode)
	}
}
