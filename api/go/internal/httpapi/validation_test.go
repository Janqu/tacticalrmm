package httpapi

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestMalformedPasswordResetCannotReachDatabase(t *testing.T) {
	server := &Server{} // No database: invalid input must be rejected before mutation.
	app := fiber.New(fiber.Config{ErrorHandler: server.handleError})
	app.Put("/", server.resetPassword)
	for _, body := range []string{`{}`, `{"password":true}`, `{"password":123}`, `{"password":[]}`, `{"password":{}}`, `{} {}`} {
		request := httptest.NewRequest("PUT", "/", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 400 {
			t.Fatalf("%s: got %d %s", body, response.StatusCode, data)
		}
	}
}
