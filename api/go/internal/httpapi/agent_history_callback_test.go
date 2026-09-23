package httpapi

import (
	"encoding/json"
	"testing"

	"gorm.io/gorm/clause"
)

func TestHistoryCallbackResults(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    *string
		present bool
		invalid bool
	}{
		{`{}`, nil, false, false}, {`{"results":null}`, nil, true, false},
		{`{"results":true}`, nil, false, true}, {`{"results":[]}`, nil, false, true},
		{`{"agent":12}`, nil, false, true}, {`{"results":"valid","type":"script_run"}`, nil, false, true},
	} {
		var input map[string]json.RawMessage
		json.Unmarshal([]byte(tc.raw), &input)
		value, present, err := historyCallbackResults(input)
		if (err != nil) != tc.invalid || present != tc.present || value != nil {
			t.Fatal(tc.raw, value, present, err)
		}
	}
	for raw, want := range map[string]string{`{"results":"  command output\n "}`: "command output", `{"results":42}`: "42", `{"results":""}`: ""} {
		var input map[string]json.RawMessage
		json.Unmarshal([]byte(raw), &input)
		value, present, err := historyCallbackResults(input)
		if err != nil || !present || value == nil || *value != want {
			t.Fatal(raw, value, present, err)
		}
	}
}

func TestScriptHistoryCallbackUpdates(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `[]`, `"output"`, `true`, `18446744073709551615`, `{"stdout":" ü ","retcode":0,"items":[null,true]}`} {
		updates, err := scriptHistoryCallbackUpdates(map[string]json.RawMessage{"script_results": json.RawMessage(raw)})
		if err != nil {
			t.Fatal(raw, err)
		}
		if raw == "null" {
			if updates["script_results"] != nil {
				t.Fatal(updates)
			}
			continue
		}
		expr, ok := updates["script_results"].(clause.Expr)
		if !ok || expr.SQL != "?::jsonb" || expr.Vars[0] != raw {
			t.Fatal("JSON value was changed", updates)
		}
	}
	for _, key := range []string{"agent", "script", "type", "username", "custom_field", "save_to_agent_note", "id"} {
		if _, err := scriptHistoryCallbackUpdates(map[string]json.RawMessage{key: json.RawMessage(`1`)}); err == nil {
			t.Fatal("accepted reassignment", key)
		}
	}
	if _, err := scriptHistoryCallbackUpdates(map[string]json.RawMessage{"script_results": json.RawMessage(`{"a":`)}); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	updates, err := scriptHistoryCallbackUpdates(map[string]json.RawMessage{"results": json.RawMessage(`"  text  "`), "script_results": json.RawMessage(`null`)})
	if err != nil || *updates["results"].(*string) != "text" {
		t.Fatal(updates, err)
	}
}

func TestCollectorCallbackValue(t *testing.T) {
	input := map[string]json.RawMessage{"script_results": json.RawMessage(`{"stdout":"\u001c first\n last \n","stderr":"ignored","retcode":1}`)}
	for all, want := range map[bool]string{true: "first\n last", false: "last"} {
		got, err := collectorCallbackValue(input, all)
		if err != nil || got != want {
			t.Fatalf("all=%v: %q %v", all, got, err)
		}
	}
	for _, raw := range []string{`null`, `[]`, `"text"`, `{}`, `{"stdout":null}`, `{"stdout":false}`, `{"stdout":123}`, `{"stdout":"bad\u0000value"}`} {
		if _, err := collectorCallbackValue(map[string]json.RawMessage{"script_results": json.RawMessage(raw)}, false); err == nil {
			t.Fatal("accepted malformed stdout", raw)
		}
	}
	if _, err := collectorCallbackValue(map[string]json.RawMessage{}, true); err == nil {
		t.Fatal("accepted missing results")
	}
}
