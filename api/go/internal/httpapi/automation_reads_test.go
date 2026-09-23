package httpapi

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestAutomationReadsRequireAuthentication(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	s.registerAutomationReads(app)
	for _, path := range []string{"/automation/policies/", "/automation/policies/1/", "/automation/policies/1/related/", "/automation/policies/overview/"} {
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
