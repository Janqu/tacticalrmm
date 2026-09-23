package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWinUpdateValidation(t *testing.T) {
	p := winUpdateParsers()
	longURL := `"https://example.invalid/` + strings.Repeat("x", 300) + `"`
	if _, err := parseFields(map[string]json.RawMessage{"support_url": json.RawMessage(longURL), "more_info_urls": json.RawMessage("[" + longURL + ",null,\"\"]")}, p); err != nil {
		t.Fatal("TextField URLs must allow more than 255 characters", err)
	}

	values, err := parseFields(map[string]json.RawMessage{"title": json.RawMessage(`"` + strings.Repeat("x", 300) + `"`), "revision_number": json.RawMessage(`"-2.0"`), "categories": json.RawMessage(`["  test  ",null,""]`), "date_installed": json.RawMessage(`"ignored"`)}, p)
	if err != nil || values["revision_number"] != int64(-2) {
		t.Fatal(values, err)
	}
	if _, ok := values["date_installed"]; ok {
		t.Fatal("date_installed must be read-only")
	}
	if _, err := parseFields(map[string]json.RawMessage{"categories": json.RawMessage(`["` + strings.Repeat("x", 256) + `"]`)}, p); err == nil {
		t.Fatal("accepted oversized category")
	}
}
