package httpapi

import (
	"encoding/json"
	"testing"
)

func TestNoteCallbackValue(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want any
	}{
		{`{"stdout":null}`, nil}, {`{"stdout":""}`, ""},
		{`{"stdout":"  text\n  ","retcode":1}`, "  text\n  "},
	} {
		got, err := noteCallbackValue(map[string]json.RawMessage{"script_results": json.RawMessage(tc.raw)})
		if err != nil || got != tc.want {
			t.Fatalf("%s: %#v %v", tc.raw, got, err)
		}
	}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"stdout":1}`, `{"stdout":false}`, `{"stdout":[]}`, `{"stdout":"bad\u0000value"}`} {
		if _, err := noteCallbackValue(map[string]json.RawMessage{"script_results": json.RawMessage(raw)}); err == nil {
			t.Fatal("accepted malformed note", raw)
		}
	}
}
