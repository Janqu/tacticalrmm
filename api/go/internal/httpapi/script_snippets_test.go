package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestSnippetCodePreservesWhitespace(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		valid     bool
	}{
		{`"  echo hi\n"`, "  echo hi\n", true}, {`"\t  "`, "\t  ", true},
		{`12`, "12", true}, {`""`, "", false}, {`null`, "", false}, {`true`, "", false},
		{`"echo\u0000hi"`, "", false},
	} {
		got, problems := snippetCode(json.RawMessage(tc.raw))
		if (len(problems) == 0) != tc.valid || (tc.valid && got != tc.want) {
			t.Errorf("%s: got %q / %v", tc.raw, got, problems)
		}
	}
}

func TestScriptSnippetsRequireAuthentication(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerScriptSnippetRoutes(app)
	for _, route := range []struct{ method, path string }{
		{"GET", "/scripts/snippets/"}, {"HEAD", "/scripts/snippets/"}, {"POST", "/scripts/snippets/"},
		{"GET", "/scripts/snippets/1/"}, {"HEAD", "/scripts/snippets/1/"}, {"PUT", "/scripts/snippets/1/"}, {"DELETE", "/scripts/snippets/1/"},
	} {
		response, err := app.Test(httptest.NewRequest(route.method, route.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Errorf("%s %s returned %d", route.method, route.path, response.StatusCode)
		}
	}
}
