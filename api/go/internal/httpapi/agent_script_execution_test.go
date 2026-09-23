package httpapi

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
)

func TestParseScriptExecution(t *testing.T) {
	base := func() map[string]json.RawMessage {
		var input map[string]json.RawMessage
		_ = json.Unmarshal([]byte(`{"script":31,"output":"wait","args":[" a "],"env_vars":["X=a=b"],"timeout":180,"run_as_user":false}`), &input)
		return input
	}
	input := base()
	got, err := parseScriptExecution(input)
	if err != nil || got.Output != "wait" || got.Timeout != 180 || got.Args[0] != " a " || got.Env[0] != "X=a=b" {
		t.Fatalf("got %#v %v", got, err)
	}
	for _, mode := range []string{"forget", "wait", "note", "note_async"} {
		input := base()
		input["output"] = json.RawMessage(`"` + mode + `"`)
		got, err := parseScriptExecution(input)
		if err != nil || got.Output != mode || got.Timeout != 180 {
			t.Fatalf("mode %s: %#v %v", mode, got, err)
		}
	}
	for _, mode := range []string{"", "async", "unknown"} {
		input := base()
		input["output"] = json.RawMessage(`"` + mode + `"`)
		if _, err := parseScriptExecution(input); err == nil {
			t.Fatalf("accepted unsupported mode %q", mode)
		}
	}
	input = base()
	input["output"] = json.RawMessage(`"collector"`)
	input["custom_field"] = json.RawMessage(`31`)
	input["save_all_output"] = json.RawMessage(`false`)
	got, err = parseScriptExecution(input)
	if err != nil || got.CustomFieldID != 31 || got.Output != "collector" || got.SaveAllOutput {
		t.Fatalf("collector input: %#v %v", got, err)
	}
	input["save_all_output"] = json.RawMessage(`"false"`)
	if _, err := parseScriptExecution(input); err == nil {
		t.Fatal("accepted nonboolean collector flag")
	}
	for key, value := range map[string]string{"output": `"email"`, "run_on_server": `true`, "args": `[null]`, "env_vars": `"wrong"`, "run_as_user": `"false"`, "timeout": `181`, "script": `true`} {
		input := base()
		input[key] = json.RawMessage(value)
		if _, err := parseScriptExecution(input); err == nil {
			t.Fatalf("accepted invalid %s", key)
		}
	}
	input = base()
	input["args"], input["env_vars"] = json.RawMessage(`null`), json.RawMessage(`null`)
	got, err = parseScriptExecution(input)
	if err != nil || len(got.Args) != 0 || len(got.Env) != 0 {
		t.Fatal("null collection compatibility changed")
	}
}

func TestScriptNoteValue(t *testing.T) {
	for _, tc := range []struct{ value, want any }{
		{nil, nil}, {"", ""}, {"  output ü\n", "  output ü\n"},
	} {
		got, err := scriptNoteValue(tc.value)
		if err != nil || got != tc.want {
			t.Fatalf("%#v: got %#v, %v", tc.value, got, err)
		}
	}
	for _, value := range []any{true, int64(1), float64(1), map[string]any{"stdout": "text"}, []any{"text"}, "bad\x00text"} {
		if _, err := scriptNoteValue(value); err == nil {
			t.Fatalf("accepted unsupported note %#v", value)
		}
	}
}

func TestScriptPublishResponse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"accepted", nil, 200, "Script will now be run on Host"},
		{"unsent", &agentbus.PublishError{Err: agentbus.ErrUnavailable}, 503, "Unable to publish the script execution request."},
		{"ambiguous", fmt.Errorf("publish: %w", &agentbus.PublishError{Err: agentbus.ErrTimeout, Ambiguous: true}), 502, "The script request may have been sent; delivery could not be confirmed."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, message := scriptPublishResponse(tc.err, "Script will now be run on Host")
			if status != tc.status || message != tc.message {
				t.Fatalf("got %d %q", status, message)
			}
		})
	}
}
