package httpapi

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
)

func enrollmentInput() map[string]json.RawMessage {
	var v map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"agent_id":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN","hostname":"enrollment-test","site":"1","monitoring_type":"workstation","plat":"linux","goarch":"amd64"}`), &v)
	return v
}

func TestAgentEnrollmentValidation(t *testing.T) {
	if _, err := parseAgentEnrollment(enrollmentInput()); err != nil {
		t.Fatal(err)
	}
	for field, values := range map[string][]string{
		"agent_id": {`"short"`, `"abcdefghijklmnopqrst.*"`, `"abcdefghijklmnopqrst abc"`},
		"site":     {`0`, `-1`, `1.5`, `true`, `null`, `"no"`}, "hostname": {`""`, `null`},
		"plat": {`"unsupported"`}, "goarch": {`"x64"`}, "monitoring_type": {`"all"`}, "description": {`"\u0000"`},
	} {
		for _, value := range values {
			input := enrollmentInput()
			input[field] = json.RawMessage(value)
			if _, err := parseAgentEnrollment(input); err == nil {
				t.Errorf("accepted %s=%s", field, value)
			}
		}
	}
}

func TestAgentInstallerHandshake(t *testing.T) {
	s := &Server{LatestAgentVersion: "2.11.0"}
	for _, test := range []struct {
		body   string
		status int
	}{{`{"version":"2.11.0"}`, 200}, {`{"version":"2.12.0"}`, 200}, {`{"version":"2.10.0"}`, 400}, {`{"version":"broken"}`, 400}, {`{}`, 400}} {
		app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error { return c.Status(400).SendString(err.Error()) }})
		app.Post("/", s.installerHandshake)
		req := httptest.NewRequest("POST", "/", strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/json")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != test.status {
			t.Errorf("%s: %d", test.body, res.StatusCode)
		}
	}
	for _, p := range []*accounts.Principal{{}, {User: accounts.User{IsInstallerUser: true}}, {User: accounts.User{IsSuperuser: true, AgentID: new(int64)}}} {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error { c.Locals("principal", p); return c.Next() }, requireEnrollment, func(c fiber.Ctx) error { return c.JSON("ok") })
		res, err := app.Test(httptest.NewRequest("GET", "/", nil))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("unprivileged enrollment: %d", res.StatusCode)
		}
	}
}
