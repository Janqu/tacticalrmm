package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestScriptExpansionSemantics(t *testing.T) {
	var seen []string
	resolve := func(key string) (any, error) { seen = append(seen, key); return `C:\temp\name`, nil }
	args, err := expandScriptArgs([]string{"x{{one}} y{{two}}", "before\n{{three}}"}, "cmd", resolve)
	if err != nil || len(seen) != 1 || seen[0] != "two" || args[0] != "xC:\temp\name" || args[1] != "before\n{{three}}" {
		t.Fatalf("unexpected greedy/escape behavior: %#v %#v %v", args, seen, err)
	}
	env, err := expandScriptEnv([]string{"bad", "A={{missing}}=lost", "B=a=b"}, "cmd", func(string) (any, error) { return nil, nil })
	if err != nil || len(env) != 1 || env[0] != "B=a=b" {
		t.Fatalf("env semantics %#v %v", env, err)
	}
	_, err = expandScriptSnippets(`{{(?=x)}}`, func(string) (string, bool, error) { return "value", true, nil })
	if err != ErrUnsupportedScriptExpansion {
		t.Fatal("unsupported Python regex must not silently expand")
	}
}

func TestScriptExpansionValues(t *testing.T) {
	text, err := formatScriptValue(ScriptObject{{"b", "ü"}, {"a", []any{json.Number("1"), true}}}, "powershell", true)
	if err != nil || text != `{"b": "\u00fc", "a": [1, true]}` {
		t.Fatalf("ordered Python JSON mismatch %q %v", text, err)
	}
	if _, err := formatScriptValue(map[string]any{"a": 1, "b": 2}, "", true); err != ErrUnsupportedScriptExpansion {
		t.Fatal("unordered object must be explicit")
	}
	if _, err := formatScriptValue([]any{1}, "cmd", false); err != ErrUnsupportedScriptExpansion {
		t.Fatal("source cannot join nonstring array")
	}
}

func TestScriptExpansionResolverFailure(t *testing.T) {
	failure := errors.New("resolver unavailable")
	result, err := expandScriptArgs([]string{"plain", "{{value}}"}, "cmd", func(string) (any, error) { return nil, failure })
	if result != nil || !errors.Is(err, failure) {
		t.Fatal("resolver failure returned partial arguments")
	}
	code, err := expandScriptSnippets("{{value}}", func(string) (string, bool, error) { return "", false, failure })
	if code != "" || !errors.Is(err, failure) {
		t.Fatal("resolver failure suppressed")
	}
}

// A test-only file bridge lets Python execute the actual Go helpers without a
// production route, database, or additional permanent executable.
func TestScriptExpansionContract(t *testing.T) {
	path := os.Getenv("TRMM_SCRIPT_EXPANSION_INPUT")
	if path == "" {
		t.Skip("Python differential driver supplies fixtures")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Mode, Shell, Code string
		Items             []string
		Values            map[string]json.RawMessage
		Snippets          map[string]string
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	outputs := []map[string]any{}
	for _, fixture := range fixtures {
		calls := []string{}
		resolve := func(key string) (any, error) {
			calls = append(calls, key)
			value := fixture.Values[key]
			if len(value) == 0 {
				return nil, nil
			}
			decoder := json.NewDecoder(strings.NewReader(string(value)))
			decoder.UseNumber()
			return decodeScriptFixture(decoder)
		}
		var value any
		var err error
		switch fixture.Mode {
		case "snippets":
			value, err = expandScriptSnippets(fixture.Code, func(name string) (string, bool, error) {
				calls = append(calls, name)
				code, found := fixture.Snippets[name]
				return code, found, nil
			})
		case "args":
			value, err = expandScriptArgs(fixture.Items, fixture.Shell, resolve)
		case "env":
			value, err = expandScriptEnv(fixture.Items, fixture.Shell, resolve)
		default:
			t.Fatal("invalid fixture mode")
		}
		out := map[string]any{"value": value, "calls": calls}
		if err != nil {
			out = map[string]any{"unsupported": true, "calls": calls}
		}
		outputs = append(outputs, out)
	}
	raw, err = json.Marshal(outputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TRMM_SCRIPT_EXPANSION_OUTPUT"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func decodeScriptFixture(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := ScriptObject{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			value, err := decodeScriptFixture(decoder)
			if err != nil {
				return nil, err
			}
			object = append(object, ScriptObjectField{key.(string), value})
		}
		_, err = decoder.Token()
		return object, err
	case json.Delim('['):
		array := []any{}
		for decoder.More() {
			value, err := decodeScriptFixture(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err = decoder.Token()
		return array, err
	default:
		if token == json.Delim('}') || token == json.Delim(']') {
			return nil, io.ErrUnexpectedEOF
		}
		return token, nil
	}
}
