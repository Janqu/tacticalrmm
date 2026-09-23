package httpapi

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestScriptReadsRequireAuthentication(t *testing.T) {
	s := &Server{}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.registerScriptReads(app)
	for _, path := range []string{"/scripts/", "/scripts/1/"} {
		for _, method := range []string{"GET", "HEAD"} {
			response, err := app.Test(httptest.NewRequest(method, path, nil))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Errorf("%s %s returned %d", method, path, response.StatusCode)
			}
		}
	}
}
